// Licensed under the Apache-2.0 license

//! SPI-flash A/B double-buffered [`ManagedEndorsementBackend`] implementation.
//!
//! Each `(role, algorithm)` allocation is subdivided into two equal ping-pong
//! regions (`0` and `1`). Replacement writes stage into the inactive region
//! while the active region remains readable, and commit by writing the
//! 76-byte [`ManagedRecord`] header with an incremented monotonic sequence
//! number.

use caliptra_mcu_cert_store::endorsement::{
    ManagedEndorsementBackend, ManagedReadHandle, CERT_MODEL_ALIAS_CERT, DEFAULT_KEY_USAGE_MASK,
    MANAGED_REGION_COUNT,
};
use caliptra_mcu_cert_store::{errors as cert_errors, CertificateAlgorithm, DeviceKey};
use caliptra_mcu_libsyscall_caliptra::flash::SpiFlash;
use caliptra_mcu_libsyscall_caliptra::DefaultSyscalls;
use caliptra_mcu_libtock_platform::ErrorCode;
use core::ops::Range;
use mcu_error::McuResult;

const MANAGED_MAGIC: [u8; 4] = *b"SPCE";
const MANAGED_FORMAT_VERSION: u16 = 2;
const MANAGED_HEADER_SIZE: usize = 76;
const MANAGED_ALGO_ECC_P384: u8 = 1;
const MANAGED_ALGO_MLDSA_87: u8 = 2;
const MANAGED_ERASED_BYTE: u8 = 0xFF;
const SPDM_CERT_CHAIN_HEADER_SIZE: usize = 4 + 48;
/// Largest DER payload the SPDM cert-chain format can describe.
const MANAGED_MAX_DER_LEN: usize = (u32::MAX as usize) - SPDM_CERT_CHAIN_HEADER_SIZE;

const fn managed_algo_code(algo: CertificateAlgorithm) -> u8 {
    match algo {
        CertificateAlgorithm::EccP384 => MANAGED_ALGO_ECC_P384,
        CertificateAlgorithm::MlDsa87 => MANAGED_ALGO_MLDSA_87,
    }
}

/// Usable DER bytes in one A/B region of a managed endorsement allocation.
pub const fn managed_endorsement_der_capacity(allocation_size: usize) -> usize {
    let region_size = allocation_size / MANAGED_REGION_COUNT;
    let available = region_size.saturating_sub(MANAGED_HEADER_SIZE);
    if available < MANAGED_MAX_DER_LEN {
        available
    } else {
        MANAGED_MAX_DER_LEN
    }
}

/// Whether two half-open byte ranges intersect.
pub fn ranges_overlap(a: &Range<usize>, b: &Range<usize>) -> bool {
    !a.is_empty() && !b.is_empty() && a.start < b.end && b.start < a.end
}

type CertStoreFlash = SpiFlash<DefaultSyscalls>;

/// Lightweight 16-byte read coordinates for an initialized managed flash
/// endorsement, captured synchronously so async flash reads do not borrow
/// the certificate store across `.await`.
#[derive(Clone, Copy)]
pub struct ManagedReadSnapshot {
    driver_num: u32,
    data_base: usize,
    len: usize,
    active_region: u8,
}

impl ManagedReadHandle for ManagedReadSnapshot {
    fn active_region(&self) -> u8 {
        self.active_region
    }

    async fn read(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let n = (self.len - offset).min(buf.len());
        CertStoreFlash::new(self.driver_num)
            .read(self.data_base + offset, n, &mut buf[..n])
            .await
            .map_err(map_flash_error)?;
        Ok(n)
    }
}

/// One managed flash-backed endorsement/root chain installed by
/// `SET_CERTIFICATE` / `MC_SET_CERT_CHAIN`.
///
/// An allocation is dedicated to a single asymmetric algorithm for its
/// lifetime, fixed when the platform wires it up, and subdivided into two
/// equal A/B ping-pong regions (`active_region` and `staging_region`) so
/// replacement writes stage in `staging_region` while `active_region`
/// remains readable.
#[derive(Clone, Copy)]
pub struct SingleManagedEndorsement {
    slot: u8,
    driver_num: u32,
    base: usize,
    capacity: usize,
    initialized: bool,
    active_region: u8,
    active_sequence: u32,
    staging_region: Option<u8>,
    algo: CertificateAlgorithm,
    len: usize,
    root_hash: [u8; 48],
    key_pair_id: u8,
    cert_info: u8,
    key_usage_mask: u16,
    device_key: Option<DeviceKey>,
}

impl SingleManagedEndorsement {
    pub const fn new(
        slot: u8,
        algo: CertificateAlgorithm,
        driver_num: u32,
        base: usize,
        capacity: usize,
        device_key: Option<DeviceKey>,
    ) -> Self {
        Self {
            slot,
            driver_num,
            base,
            capacity,
            initialized: false,
            active_region: 0,
            active_sequence: 0,
            staging_region: None,
            algo,
            len: 0,
            root_hash: [0; 48],
            key_pair_id: 0,
            cert_info: 0,
            key_usage_mask: DEFAULT_KEY_USAGE_MASK,
            device_key,
        }
    }

    pub async fn load(&mut self) -> McuResult<()> {
        self.discard();
        if !self.capacity.is_multiple_of(MANAGED_REGION_COUNT) || self.der_capacity() == 0 {
            return Err(mcu_error::codes::INVARIANT);
        }
        let flash = self.flash();
        match flash.exists() {
            Ok(()) => {}
            Err(ErrorCode::NoDevice | ErrorCode::NoSupport | ErrorCode::Uninstalled) => {
                return Ok(())
            }
            Err(err) => return Err(map_flash_error(err)),
        }
        let mut selected: Option<(u8, ManagedRecord)> = None;
        for region in 0..(MANAGED_REGION_COUNT as u8) {
            let Some(record) = self.load_region(&flash, region).await? else {
                continue;
            };
            let replace = match &selected {
                None => true,
                Some((_, current)) => record.sequence > current.sequence,
            };
            if replace {
                selected = Some((region, record));
            }
        }
        if let Some((region, record)) = selected {
            self.initialized = true;
            self.active_region = region;
            self.active_sequence = record.sequence;
            self.len = record.cert_len;
            self.root_hash = record.root_hash;
            self.key_pair_id = record.key_pair_id;
            self.cert_info = record.cert_info;
            self.key_usage_mask = record.key_usage_mask;
        }
        Ok(())
    }

    async fn load_region(
        &self,
        flash: &CertStoreFlash,
        region: u8,
    ) -> McuResult<Option<ManagedRecord>> {
        let mut header = [0u8; MANAGED_HEADER_SIZE];
        flash
            .read(self.region_base(region), MANAGED_HEADER_SIZE, &mut header)
            .await
            .map_err(map_flash_error)?;
        if header.iter().all(|&b| b == MANAGED_ERASED_BYTE) {
            return Ok(None);
        }
        let Some(record) = ManagedRecord::decode(&header) else {
            return Ok(None);
        };
        if self.validate_record(&record).is_err() {
            return Ok(None);
        }
        if self.stored_checksum(region, record.cert_len).await? != record.data_checksum {
            return Ok(None);
        }
        Ok(Some(record))
    }

    fn validate_record(&self, record: &ManagedRecord) -> McuResult<()> {
        if !self.capacity.is_multiple_of(MANAGED_REGION_COUNT)
            || record.version != MANAGED_FORMAT_VERSION
            || record.header_size as usize != MANAGED_HEADER_SIZE
            || record.slot != self.slot
            || record.algo != managed_algo_code(self.algo)
            || record.cert_len > self.der_capacity()
            || record.cert_len == 0
            || record.key_usage_mask != DEFAULT_KEY_USAGE_MASK
        {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        self.validate_metadata(record.key_pair_id, record.cert_info)
    }

    fn validate_metadata(&self, key_pair_id: u8, cert_info: u8) -> McuResult<()> {
        let key = DeviceKey::from_key_pair_id(key_pair_id).ok_or(cert_errors::KEY_MISMATCH)?;
        if let Some(expected) = self.device_key {
            if key != expected {
                return Err(cert_errors::KEY_MISMATCH);
            }
        }
        key.validate_anchor_point()?;
        if cert_info != CERT_MODEL_ALIAS_CERT {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        Ok(())
    }

    fn validate_erase(&self) -> McuResult<()> {
        if let Some(key) = self.device_key {
            key.validate_anchor_point()?;
        }
        Ok(())
    }

    #[cfg(test)]
    const fn active_region(&self) -> Option<u8> {
        if self.initialized {
            Some(self.active_region)
        } else {
            None
        }
    }

    pub const fn inactive_region(&self) -> u8 {
        if self.initialized {
            1 - (self.active_region & 1)
        } else {
            0
        }
    }

    const fn next_sequence(&self) -> u32 {
        self.active_sequence.wrapping_add(1)
    }

    async fn commit_record_to_region(&self, region: u8, record: &ManagedRecord) -> McuResult<()> {
        let mut header = [MANAGED_ERASED_BYTE; MANAGED_HEADER_SIZE];
        record.encode(&mut header);
        self.flash()
            .write(self.region_base(region), MANAGED_HEADER_SIZE, &header)
            .await
            .map_err(map_flash_error)?;
        Ok(())
    }

    fn flash(&self) -> CertStoreFlash {
        CertStoreFlash::new(self.driver_num)
    }

    async fn stored_checksum(&self, region: u8, len: usize) -> McuResult<u32> {
        let mut remaining = len;
        let mut offset = 0usize;
        let mut sum = 0u32;
        let mut chunk = [0u8; 256];
        let flash = self.flash();
        let data_base = self.region_data_base(region);
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            flash
                .read(data_base + offset, n, &mut chunk[..n])
                .await
                .map_err(map_flash_error)?;
            sum = sum.wrapping_add(checksum(&chunk[..n]));
            remaining -= n;
            offset += n;
        }
        Ok(sum)
    }

    const fn region_capacity(&self) -> usize {
        self.capacity / MANAGED_REGION_COUNT
    }

    const fn region_base(&self, region: u8) -> usize {
        self.base + ((region as usize) % MANAGED_REGION_COUNT) * self.region_capacity()
    }

    const fn region_data_base(&self, region: u8) -> usize {
        self.region_base(region) + MANAGED_HEADER_SIZE
    }

    /// The flash region this chain occupies, as a half-open range.
    pub fn region_range(&self) -> Range<usize> {
        self.base..self.base.saturating_add(self.capacity)
    }

    /// Whether this chain's flash region intersects `range` on the
    /// flash device `driver_num`.
    pub fn region_overlaps(&self, driver_num: u32, range: &Range<usize>) -> bool {
        self.driver_num == driver_num && ranges_overlap(&self.region_range(), range)
    }

    #[cfg(test)]
    async fn read(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        self.read_snapshot()?.read(offset, buf).await
    }
}

impl ManagedEndorsementBackend for SingleManagedEndorsement {
    type ReadHandle = ManagedReadSnapshot;

    fn algo(&self) -> CertificateAlgorithm {
        self.algo
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }

    fn der_capacity(&self) -> usize {
        managed_endorsement_der_capacity(self.capacity)
    }

    fn size(&self) -> McuResult<usize> {
        if self.initialized {
            Ok(self.len)
        } else {
            Err(mcu_error::codes::INVARIANT)
        }
    }

    fn root_cert_hash(&self, out: &mut [u8]) -> McuResult<()> {
        if !self.initialized {
            return Err(mcu_error::codes::INVARIANT);
        }
        let n = out.len().min(self.root_hash.len());
        out[..n].copy_from_slice(&self.root_hash[..n]);
        Ok(())
    }

    fn key_pair_id(&self) -> Option<u8> {
        self.initialized.then_some(self.key_pair_id)
    }

    fn cert_info(&self) -> Option<u8> {
        self.initialized.then_some(self.cert_info)
    }

    fn key_usage_mask(&self) -> Option<u16> {
        self.initialized.then_some(self.key_usage_mask)
    }

    fn staging_region(&self) -> Option<u8> {
        Some(self.inactive_region())
    }

    fn read_snapshot(&self) -> McuResult<Self::ReadHandle> {
        if !self.initialized {
            return Err(mcu_error::codes::INVARIANT);
        }
        Ok(ManagedReadSnapshot {
            driver_num: self.driver_num,
            data_base: self.region_data_base(self.active_region),
            len: self.len,
            active_region: self.active_region,
        })
    }

    fn discard(&mut self) {
        self.initialized = false;
        self.active_region = 0;
        self.active_sequence = 0;
        self.staging_region = None;
        self.len = 0;
        self.root_hash = [0; 48];
        self.key_pair_id = 0;
        self.cert_info = 0;
    }

    fn abort_stream_update(&mut self) {
        self.staging_region = None;
    }

    async fn begin_stream_update(
        mut self,
        key_pair_id: u8,
        cert_info: u8,
        data_len: usize,
    ) -> McuResult<Self> {
        self.validate_metadata(key_pair_id, cert_info)?;
        if !self.capacity.is_multiple_of(MANAGED_REGION_COUNT)
            || data_len == 0
            || data_len > self.der_capacity()
        {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        let target_region = self.inactive_region();
        self.flash()
            .erase(self.region_base(target_region), self.region_capacity())
            .await
            .map_err(map_flash_error)?;
        self.staging_region = Some(target_region);
        Ok(self)
    }

    async fn write_stream_chunk(&self, offset: usize, data: &[u8]) -> McuResult<()> {
        let region = self.staging_region.ok_or(mcu_error::codes::INVARIANT)?;
        let end = offset
            .checked_add(data.len())
            .ok_or(mcu_error::codes::INVARIANT)?;
        if end > self.der_capacity() {
            return Err(mcu_error::codes::INVARIANT);
        }
        if !data.is_empty() {
            self.flash()
                .write(self.region_data_base(region) + offset, data.len(), data)
                .await
                .map_err(map_flash_error)?;
        }
        Ok(())
    }

    async fn read_stream_chunk(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
        let region = self.staging_region.ok_or(mcu_error::codes::INVARIANT)?;
        if offset >= self.der_capacity() || buf.is_empty() {
            return Ok(0);
        }
        let n = (self.der_capacity() - offset).min(buf.len());
        self.flash()
            .read(self.region_data_base(region) + offset, n, &mut buf[..n])
            .await
            .map_err(map_flash_error)?;
        Ok(n)
    }

    async fn finish_stream_update(
        mut self,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data_len: usize,
    ) -> McuResult<Self> {
        self.validate_metadata(key_pair_id, cert_info)?;
        if !self.capacity.is_multiple_of(MANAGED_REGION_COUNT)
            || data_len == 0
            || data_len > self.der_capacity()
        {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }
        let region = self.staging_region.ok_or(mcu_error::codes::INVARIANT)?;
        let data_checksum = self.stored_checksum(region, data_len).await?;
        let sequence = self.next_sequence();
        let record = ManagedRecord {
            version: MANAGED_FORMAT_VERSION,
            header_size: MANAGED_HEADER_SIZE as u16,
            slot: self.slot,
            algo: managed_algo_code(self.algo),
            key_pair_id,
            cert_info,
            key_usage_mask: DEFAULT_KEY_USAGE_MASK,
            cert_len: data_len,
            data_checksum,
            root_hash: *root_hash,
            sequence,
        };
        self.commit_record_to_region(region, &record).await?;
        self.initialized = true;
        self.active_region = region;
        self.active_sequence = sequence;
        self.staging_region = None;
        self.len = data_len;
        self.root_hash = *root_hash;
        self.key_pair_id = key_pair_id;
        self.cert_info = cert_info;
        self.key_usage_mask = DEFAULT_KEY_USAGE_MASK;
        Ok(self)
    }

    async fn write_updated(
        mut self,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data: &[u8],
    ) -> McuResult<Self> {
        self.validate_metadata(key_pair_id, cert_info)?;
        if !self.capacity.is_multiple_of(MANAGED_REGION_COUNT)
            || data.is_empty()
            || data.len() > self.der_capacity()
        {
            return Err(cert_errors::INVALID_ENDORSEMENT);
        }

        let region = self.inactive_region();
        let expected_checksum = checksum(data);
        let sequence = self.next_sequence();
        let record = ManagedRecord {
            version: MANAGED_FORMAT_VERSION,
            header_size: MANAGED_HEADER_SIZE as u16,
            slot: self.slot,
            algo: managed_algo_code(self.algo),
            key_pair_id,
            cert_info,
            key_usage_mask: DEFAULT_KEY_USAGE_MASK,
            cert_len: data.len(),
            data_checksum: expected_checksum,
            root_hash: *root_hash,
            sequence,
        };

        let flash = self.flash();
        flash
            .erase(self.region_base(region), self.region_capacity())
            .await
            .map_err(map_flash_error)?;
        flash
            .write(self.region_data_base(region), data.len(), data)
            .await
            .map_err(map_flash_error)?;
        if self.stored_checksum(region, data.len()).await? != expected_checksum {
            return Err(cert_errors::STORAGE_ERROR);
        }
        self.commit_record_to_region(region, &record).await?;

        self.initialized = true;
        self.active_region = region;
        self.active_sequence = sequence;
        self.staging_region = None;
        self.len = data.len();
        self.root_hash = *root_hash;
        self.key_pair_id = key_pair_id;
        self.cert_info = cert_info;
        self.key_usage_mask = DEFAULT_KEY_USAGE_MASK;
        Ok(self)
    }

    async fn erase_updated(mut self) -> McuResult<Self> {
        self.validate_erase()?;
        if !self.capacity.is_multiple_of(MANAGED_REGION_COUNT) {
            return Err(mcu_error::codes::INVARIANT);
        }
        let active_region = self.active_region & 1;
        let staging_region = 1 - active_region;
        let region_cap = self.region_capacity();
        let flash = self.flash();
        // Erase the staging (superseded) region first, then the active region, so
        // an interrupted erase can never resurrect an older region after reset.
        flash
            .erase(self.region_base(staging_region), region_cap)
            .await
            .map_err(map_flash_error)?;
        flash
            .erase(self.region_base(active_region), region_cap)
            .await
            .map_err(map_flash_error)?;
        self.discard();
        self.key_usage_mask = DEFAULT_KEY_USAGE_MASK;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManagedRecord {
    version: u16,
    header_size: u16,
    slot: u8,
    algo: u8,
    key_pair_id: u8,
    cert_info: u8,
    key_usage_mask: u16,
    cert_len: usize,
    data_checksum: u32,
    root_hash: [u8; 48],
    sequence: u32,
}

impl ManagedRecord {
    fn encode(&self, out: &mut [u8; MANAGED_HEADER_SIZE]) {
        // Layout (matches decode below):
        //   [0..4]   magic ("SPCE")
        //   [4..6]   version (LE)
        //   [6..8]   header_size (LE)
        //   [8]      slot
        //   [9]      algo
        //   [10]     key_pair_id
        //   [11]     cert_info
        //   [12..14] key_usage_mask (LE)
        //   [14..16] reserved
        //   [16..20] cert_len (LE u32)
        //   [20..24] data_checksum (LE)
        //   [24..72] root_hash
        //   [72..76] sequence (LE u32)
        out[0..4].copy_from_slice(&MANAGED_MAGIC);
        out[4..6].copy_from_slice(&self.version.to_le_bytes());
        out[6..8].copy_from_slice(&self.header_size.to_le_bytes());
        out[8] = self.slot;
        out[9] = self.algo;
        out[10] = self.key_pair_id;
        out[11] = self.cert_info;
        out[12..14].copy_from_slice(&self.key_usage_mask.to_le_bytes());
        out[14..16].copy_from_slice(&[0, 0]);
        out[16..20].copy_from_slice(&(self.cert_len as u32).to_le_bytes());
        out[20..24].copy_from_slice(&self.data_checksum.to_le_bytes());
        out[24..72].copy_from_slice(&self.root_hash);
        out[72..76].copy_from_slice(&self.sequence.to_le_bytes());
    }

    fn decode(input: &[u8; MANAGED_HEADER_SIZE]) -> Option<Self> {
        let (magic, rest) = input.split_first_chunk::<4>()?;
        if magic != &MANAGED_MAGIC {
            return None;
        }
        let (version, rest) = rest.split_first_chunk::<2>()?;
        let (header_size, rest) = rest.split_first_chunk::<2>()?;
        let (slot, rest) = rest.split_first()?;
        let (algo, rest) = rest.split_first()?;
        let (key_pair_id, rest) = rest.split_first()?;
        let (cert_info, rest) = rest.split_first()?;
        let (kum, rest) = rest.split_first_chunk::<2>()?;
        let (_reserved, rest) = rest.split_first_chunk::<2>()?;
        let (cert_len, rest) = rest.split_first_chunk::<4>()?;
        let (data_checksum, rest) = rest.split_first_chunk::<4>()?;
        let (root_hash, rest) = rest.split_first_chunk::<48>()?;
        let (sequence, _) = rest.split_first_chunk::<4>()?;
        Some(Self {
            version: u16::from_le_bytes(*version),
            header_size: u16::from_le_bytes(*header_size),
            slot: *slot,
            algo: *algo,
            key_pair_id: *key_pair_id,
            cert_info: *cert_info,
            key_usage_mask: u16::from_le_bytes(*kum),
            cert_len: u32::from_le_bytes(*cert_len) as usize,
            data_checksum: u32::from_le_bytes(*data_checksum),
            root_hash: *root_hash,
            sequence: u32::from_le_bytes(*sequence),
        })
    }
}

fn checksum(data: &[u8]) -> u32 {
    data.iter()
        .fold(0u32, |acc, &byte| acc.wrapping_add(byte as u32))
}

fn map_flash_error(err: ErrorCode) -> mcu_error::McuErrorCode {
    match err {
        ErrorCode::Busy => cert_errors::STORAGE_BUSY,
        _ => cert_errors::STORAGE_ERROR,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use caliptra_mcu_cert_store::endorsement::{ManagedEndorsementSlot, SlotEndorsement};
    use CertificateAlgorithm as SpdmPalAsymAlgo;

    // Image partition exposed by FakeFlashDriver.
    const TEST_DRIVER: u32 = 0x8000_0006;
    const TEST_REGION: usize = 4096;

    fn chain(algo: SpdmPalAsymAlgo, base: usize) -> SingleManagedEndorsement {
        SingleManagedEndorsement::new(
            2,
            algo,
            TEST_DRIVER,
            base,
            TEST_REGION,
            Some(DeviceKey::LDevId),
        )
    }

    fn span(base: usize) -> Range<usize> {
        base..base + TEST_REGION
    }

    #[test]
    fn ranges_overlap_detects_any_intersection() {
        let region = span(TEST_REGION);

        assert!(ranges_overlap(&region, &span(TEST_REGION)));
        assert!(ranges_overlap(&region, &span(TEST_REGION / 2)));
        assert!(ranges_overlap(
            &region,
            &span(TEST_REGION + TEST_REGION / 2)
        ));
        assert!(ranges_overlap(&region, &(0..TEST_REGION * 4)));
        assert!(ranges_overlap(&(0..TEST_REGION * 4), &span(TEST_REGION)));
        assert!(!ranges_overlap(&region, &span(0)));
        assert!(!ranges_overlap(&region, &span(TEST_REGION * 2)));
        assert!(!ranges_overlap(&region, &(TEST_REGION..TEST_REGION)));
        assert!(!ranges_overlap(
            &(TEST_REGION..TEST_REGION),
            &(TEST_REGION..TEST_REGION)
        ));
        assert!(!ranges_overlap(
            &(TEST_REGION + 5..TEST_REGION + 5),
            &region
        ));
        assert!(!ranges_overlap(
            &region,
            &(TEST_REGION + 5..TEST_REGION + 5)
        ));
    }

    #[test]
    fn region_overlap_is_scoped_to_one_flash_device() {
        let ecc = chain(SpdmPalAsymAlgo::EccP384, TEST_REGION);

        assert_eq!(ecc.region_range(), span(TEST_REGION));
        assert!(ecc.region_overlaps(TEST_DRIVER, &span(TEST_REGION)));
        assert!(!ecc.region_overlaps(TEST_DRIVER + 1, &span(TEST_REGION)));
    }

    #[test]
    fn managed_regions_are_provisioned_independently() {
        let mut ecc = chain(SpdmPalAsymAlgo::EccP384, 0);
        let mldsa = chain(SpdmPalAsymAlgo::MlDsa87, TEST_REGION);

        let slot = ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa);
        assert!(!SlotEndorsement::Managed(slot).is_provisioned(SpdmPalAsymAlgo::EccP384));
        assert!(!SlotEndorsement::Managed(slot).is_provisioned(SpdmPalAsymAlgo::MlDsa87));

        ecc.initialized = true;
        let slot = ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa);
        let endorsement = SlotEndorsement::Managed(slot);
        assert!(endorsement.is_provisioned(SpdmPalAsymAlgo::EccP384));
        assert!(!endorsement.is_provisioned(SpdmPalAsymAlgo::MlDsa87));

        let mut mldsa = mldsa;
        mldsa.initialized = true;
        let endorsement =
            SlotEndorsement::Managed(ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa));
        assert!(endorsement.is_provisioned(SpdmPalAsymAlgo::EccP384));
        assert!(endorsement.is_provisioned(SpdmPalAsymAlgo::MlDsa87));
    }

    #[test]
    fn managed_algo_codes_are_distinct() {
        assert_eq!(
            managed_algo_code(SpdmPalAsymAlgo::EccP384),
            MANAGED_ALGO_ECC_P384
        );
        assert_eq!(
            managed_algo_code(SpdmPalAsymAlgo::MlDsa87),
            MANAGED_ALGO_MLDSA_87
        );
        assert_ne!(MANAGED_ALGO_ECC_P384, MANAGED_ALGO_MLDSA_87);
    }

    #[test]
    fn managed_record_round_trips() {
        let record = ManagedRecord {
            version: MANAGED_FORMAT_VERSION,
            header_size: MANAGED_HEADER_SIZE as u16,
            slot: 2,
            algo: MANAGED_ALGO_ECC_P384,
            key_pair_id: 7,
            cert_info: 3,
            key_usage_mask: 0x0003,
            cert_len: 1234,
            data_checksum: 0xfeed_beef,
            root_hash: [0x5a; 48],
            sequence: 42,
        };
        let mut buf = [MANAGED_ERASED_BYTE; MANAGED_HEADER_SIZE];
        record.encode(&mut buf);
        assert_eq!(&buf[0..4], &MANAGED_MAGIC);
        assert_eq!(ManagedRecord::decode(&buf), Some(record));
    }

    #[test]
    fn managed_capacity_excludes_header() {
        let endorsement = chain(SpdmPalAsymAlgo::EccP384, 0);
        assert_eq!(
            endorsement.der_capacity(),
            TEST_REGION / MANAGED_REGION_COUNT - MANAGED_HEADER_SIZE
        );
    }

    #[test]
    fn managed_der_capacity_obeys_cert_chain_format_limit() {
        assert_eq!(
            managed_endorsement_der_capacity(usize::MAX),
            u32::MAX as usize - SPDM_CERT_CHAIN_HEADER_SIZE
        );
    }

    #[test]
    fn managed_der_capacity_is_region_bound_past_64kib() {
        let region = 256 * 1024;
        assert_eq!(
            managed_endorsement_der_capacity(region),
            region / MANAGED_REGION_COUNT - MANAGED_HEADER_SIZE
        );
        assert!(managed_endorsement_der_capacity(region) > u16::MAX as usize);
    }

    #[test]
    fn managed_endorsements_share_the_configured_key_pair_id() {
        let mut ecc = chain(SpdmPalAsymAlgo::EccP384, 0);
        let mut mldsa = chain(SpdmPalAsymAlgo::MlDsa87, TEST_REGION);

        ecc.initialized = true;
        ecc.key_pair_id = 1;
        ecc.cert_info = CERT_MODEL_ALIAS_CERT;

        mldsa.initialized = true;
        mldsa.key_pair_id = 1;
        mldsa.cert_info = CERT_MODEL_ALIAS_CERT;

        let slot = ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa);
        assert_eq!(
            slot.get_endorsement(SpdmPalAsymAlgo::EccP384)
                .unwrap()
                .key_pair_id(),
            Some(1)
        );
        assert_eq!(
            slot.get_endorsement(SpdmPalAsymAlgo::MlDsa87)
                .unwrap()
                .key_pair_id(),
            Some(1)
        );
        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            let endorsement = slot.get_endorsement(algo).unwrap();
            assert_eq!(
                endorsement.validate_metadata(1, CERT_MODEL_ALIAS_CERT),
                Ok(())
            );
            assert_eq!(
                endorsement.validate_metadata(2, CERT_MODEL_ALIAS_CERT),
                Err(cert_errors::KEY_MISMATCH)
            );
        }
    }

    #[test]
    fn wrong_key_is_rejected_before_ordinary_or_streamed_flash_writes() {
        use caliptra_mcu_libtock_unittest::fake;
        use std::boxed::Box;

        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            for provisioned in [false, true] {
                let mut region = chain(algo, 0);
                region.initialized = provisioned;
                for id in [0, 2, 3, 255] {
                    assert_eq!(
                        fake::wait_for_future_ready(Box::pin(region.write_updated(
                            id,
                            CERT_MODEL_ALIAS_CERT,
                            &[0; 48],
                            &[1]
                        )))
                        .err(),
                        Some(cert_errors::KEY_MISMATCH),
                    );
                    assert_eq!(
                        fake::wait_for_future_ready(Box::pin(region.begin_stream_update(
                            id,
                            CERT_MODEL_ALIAS_CERT,
                            1
                        )))
                        .err(),
                        Some(cert_errors::KEY_MISMATCH),
                    );
                }
            }
        }
    }

    #[test]
    fn none_policy_allows_explicit_supported_key_and_rejects_invalid_ids() {
        use caliptra_mcu_libtock_unittest::fake;
        use std::boxed::Box;

        let mut region = chain(SpdmPalAsymAlgo::EccP384, 0);
        region.device_key = None;
        assert_eq!(region.validate_metadata(1, CERT_MODEL_ALIAS_CERT), Ok(()));
        assert_eq!(
            region.validate_metadata(0, CERT_MODEL_ALIAS_CERT),
            Err(cert_errors::KEY_MISMATCH)
        );
        for id in [2, 3] {
            assert_eq!(
                region.validate_metadata(id, CERT_MODEL_ALIAS_CERT),
                Err(cert_errors::UNSUPPORTED_KEY)
            );
            assert_eq!(
                fake::wait_for_future_ready(Box::pin(region.begin_stream_update(
                    id,
                    CERT_MODEL_ALIAS_CERT,
                    1
                )))
                .err(),
                Some(cert_errors::UNSUPPORTED_KEY),
            );
        }
    }

    #[test]
    fn recovery_rejects_old_ids_and_unsupported_models() {
        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            let region = chain(algo, 0);
            let record = ManagedRecord {
                version: MANAGED_FORMAT_VERSION,
                header_size: MANAGED_HEADER_SIZE as u16,
                slot: 2,
                algo: managed_algo_code(algo),
                key_pair_id: 1,
                cert_info: CERT_MODEL_ALIAS_CERT,
                key_usage_mask: DEFAULT_KEY_USAGE_MASK,
                cert_len: 123,
                data_checksum: 0,
                root_hash: [0; 48],
                sequence: 1,
            };
            assert_eq!(region.validate_record(&record), Ok(()));
            assert_eq!(
                region.validate_record(&ManagedRecord {
                    version: 1,
                    ..record
                }),
                Err(cert_errors::INVALID_ENDORSEMENT),
            );
            for id in [0, 2, 3] {
                assert_eq!(
                    region.validate_record(&ManagedRecord {
                        key_pair_id: id,
                        ..record
                    }),
                    Err(cert_errors::KEY_MISMATCH),
                );
            }
            assert_eq!(
                region.validate_record(&ManagedRecord {
                    cert_info: 1,
                    ..record
                }),
                Err(cert_errors::INVALID_ENDORSEMENT),
            );
            let mut unrestricted = region;
            unrestricted.device_key = None;
            assert_eq!(unrestricted.validate_record(&record), Ok(()));
            assert_eq!(
                unrestricted.validate_record(&ManagedRecord {
                    key_pair_id: 0,
                    ..record
                }),
                Err(cert_errors::KEY_MISMATCH),
            );
            assert_eq!(
                unrestricted.validate_record(&ManagedRecord {
                    key_pair_id: 2,
                    ..record
                }),
                Err(cert_errors::UNSUPPORTED_KEY),
            );
        }
    }

    #[test]
    fn stream_commit_rejects_key_and_model_before_flash_access() {
        use caliptra_mcu_libtock_unittest::fake;
        use std::boxed::Box;

        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            let region = chain(algo, 0);
            for (id, model, error) in [
                (0, CERT_MODEL_ALIAS_CERT, cert_errors::KEY_MISMATCH),
                (2, CERT_MODEL_ALIAS_CERT, cert_errors::KEY_MISMATCH),
                (1, 1, cert_errors::INVALID_ENDORSEMENT),
            ] {
                assert_eq!(
                    fake::wait_for_future_ready(Box::pin(
                        region.finish_stream_update(id, model, &[3; 48], 100)
                    ))
                    .err(),
                    Some(error),
                );
            }
        }
    }

    #[test]
    fn discarding_data_does_not_change_the_binding() {
        let mut region = chain(SpdmPalAsymAlgo::EccP384, 0);
        region.initialized = true;
        region.key_pair_id = 1;
        region.cert_info = CERT_MODEL_ALIAS_CERT;
        region.discard();
        assert_eq!(region.key_pair_id(), None);
        assert_eq!(region.validate_metadata(1, CERT_MODEL_ALIAS_CERT), Ok(()));
        assert_eq!(
            region.validate_metadata(2, CERT_MODEL_ALIAS_CERT),
            Err(cert_errors::KEY_MISMATCH)
        );
    }

    #[test]
    fn flash_replacement_removal_and_recovery_preserve_the_configured_identity() {
        use caliptra_mcu_libtock_unittest::fake;
        use std::{boxed::Box, rc::Rc, vec};

        let kernel = fake::Kernel::new();
        let flash = Rc::new(fake::FakeFlashDriver::new());
        flash.set_flash_content(vec![MANAGED_ERASED_BYTE; 2 * TEST_REGION]);
        kernel.add_driver(&flash);
        let mut ecc = chain(SpdmPalAsymAlgo::EccP384, 0);
        let mldsa = chain(SpdmPalAsymAlgo::MlDsa87, TEST_REGION);
        let mldsa = fake::wait_for_future_ready(Box::pin(mldsa.write_updated(
            1,
            CERT_MODEL_ALIAS_CERT,
            &[2; 48],
            &[2; 16],
        )))
        .unwrap();
        fake::wait_for_future_ready(Box::pin(ecc.load())).unwrap();
        assert!(!ecc.is_initialized());
        assert_eq!(mldsa.key_pair_id(), Some(1));

        for (algo, base) in [
            (SpdmPalAsymAlgo::EccP384, 0),
            (SpdmPalAsymAlgo::MlDsa87, TEST_REGION),
        ] {
            let mut region = chain(algo, base);
            for byte in [3, 4] {
                region = fake::wait_for_future_ready(Box::pin(region.write_updated(
                    1,
                    CERT_MODEL_ALIAS_CERT,
                    &[byte; 48],
                    &[byte; 16],
                )))
                .unwrap();
                let mut recovered = chain(algo, base);
                fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
                assert_eq!(recovered.key_pair_id(), Some(1));
                let mut data = [0; 16];
                assert_eq!(
                    fake::wait_for_future_ready(Box::pin(recovered.read(0, &mut data))),
                    Ok(16)
                );
                assert_eq!(data, [byte; 16]);
            }
            let mut unrestricted = region;
            unrestricted.device_key = None;
            fake::wait_for_future_ready(Box::pin(unrestricted.load())).unwrap();
            assert_eq!(unrestricted.key_pair_id(), Some(1));
            fake::wait_for_future_ready(Box::pin(region.load())).unwrap();
            assert_eq!(region.key_pair_id(), Some(1));

            region = fake::wait_for_future_ready(Box::pin(region.erase_updated())).unwrap();
            fake::wait_for_future_ready(Box::pin(region.load())).unwrap();
            assert!(!region.is_initialized());
            region = fake::wait_for_future_ready(Box::pin(region.write_updated(
                1,
                CERT_MODEL_ALIAS_CERT,
                &[5; 48],
                &[5; 16],
            )))
            .unwrap();
            fake::wait_for_future_ready(Box::pin(region.load())).unwrap();
            assert_eq!(region.key_pair_id(), Some(1));
        }
    }

    #[test]
    fn streamed_flash_record_is_not_published_with_changed_metadata() {
        use caliptra_mcu_libtock_unittest::fake;
        use std::{boxed::Box, rc::Rc, vec};

        let kernel = fake::Kernel::new();
        let flash = Rc::new(fake::FakeFlashDriver::new());
        flash.set_flash_content(vec![MANAGED_ERASED_BYTE; TEST_REGION]);
        kernel.add_driver(&flash);
        for algo in [SpdmPalAsymAlgo::EccP384, SpdmPalAsymAlgo::MlDsa87] {
            let mut region = chain(algo, 0);
            region = fake::wait_for_future_ready(Box::pin(region.begin_stream_update(
                1,
                CERT_MODEL_ALIAS_CERT,
                16,
            )))
            .unwrap();
            fake::wait_for_future_ready(Box::pin(region.write_stream_chunk(0, &[4; 8]))).unwrap();
            fake::wait_for_future_ready(Box::pin(region.write_stream_chunk(8, &[5; 8]))).unwrap();
            assert_eq!(
                fake::wait_for_future_ready(Box::pin(region.finish_stream_update(
                    2,
                    CERT_MODEL_ALIAS_CERT,
                    &[3; 48],
                    16,
                )))
                .err(),
                Some(cert_errors::KEY_MISMATCH),
            );
            let mut recovered = region;
            fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
            assert!(!recovered.is_initialized());
            region = fake::wait_for_future_ready(Box::pin(region.finish_stream_update(
                1,
                CERT_MODEL_ALIAS_CERT,
                &[3; 48],
                16,
            )))
            .unwrap();
            fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
            assert_eq!(recovered.key_pair_id(), Some(1));
            assert_eq!(region.key_pair_id(), Some(1));
        }
    }

    #[test]
    fn ab_region_ping_pong_preserves_active_region_during_stream_and_abort() {
        use caliptra_mcu_libtock_unittest::fake;
        use std::{boxed::Box, rc::Rc, vec};

        let kernel = fake::Kernel::new();
        let flash = Rc::new(fake::FakeFlashDriver::new());
        flash.set_flash_content(vec![MANAGED_ERASED_BYTE; TEST_REGION]);
        kernel.add_driver(&flash);

        // 1. Initial write lands in region 0 with sequence 1.
        let region = chain(SpdmPalAsymAlgo::EccP384, 0);
        let region = fake::wait_for_future_ready(Box::pin(region.write_updated(
            1,
            CERT_MODEL_ALIAS_CERT,
            &[0x11; 48],
            &[0xAA; 16],
        )))
        .unwrap();
        assert_eq!(region.active_region(), Some(0));
        assert_eq!(region.inactive_region(), 1);

        // 2. Begin streaming replacement into region 1 while region 0 stays active and readable.
        let mut staging = fake::wait_for_future_ready(Box::pin(region.begin_stream_update(
            1,
            CERT_MODEL_ALIAS_CERT,
            16,
        )))
        .unwrap();
        fake::wait_for_future_ready(Box::pin(staging.write_stream_chunk(0, &[0xBB; 16]))).unwrap();

        let mut active_bytes = [0u8; 16];
        assert_eq!(
            fake::wait_for_future_ready(Box::pin(staging.read(0, &mut active_bytes))),
            Ok(16)
        );
        assert_eq!(active_bytes, [0xAA; 16]);

        // Simulated power loss mid-stream: load() recovers region 0 because region 1 has no committed header.
        let mut recovered = chain(SpdmPalAsymAlgo::EccP384, 0);
        fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
        assert_eq!(recovered.active_region(), Some(0));
        let mut rec_bytes = [0u8; 16];
        fake::wait_for_future_ready(Box::pin(recovered.read(0, &mut rec_bytes))).unwrap();
        assert_eq!(rec_bytes, [0xAA; 16]);

        // Aborting stream leaves region 0 intact.
        staging.abort_stream_update();
        assert!(staging.is_initialized());
        assert_eq!(staging.active_region(), Some(0));

        // 3. Re-stream and commit to region 1 (sequence 2).
        let staging = fake::wait_for_future_ready(Box::pin(staging.begin_stream_update(
            1,
            CERT_MODEL_ALIAS_CERT,
            16,
        )))
        .unwrap();
        fake::wait_for_future_ready(Box::pin(staging.write_stream_chunk(0, &[0xBB; 16]))).unwrap();
        let region = fake::wait_for_future_ready(Box::pin(staging.finish_stream_update(
            1,
            CERT_MODEL_ALIAS_CERT,
            &[0x22; 48],
            16,
        )))
        .unwrap();
        assert_eq!(region.active_region(), Some(1));
        fake::wait_for_future_ready(Box::pin(region.read(0, &mut active_bytes))).unwrap();
        assert_eq!(active_bytes, [0xBB; 16]);

        // Reboot recovery picks region 1 (sequence 2 > region 0 sequence 1).
        let mut recovered = chain(SpdmPalAsymAlgo::EccP384, 0);
        fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
        assert_eq!(recovered.active_region(), Some(1));
        fake::wait_for_future_ready(Box::pin(recovered.read(0, &mut rec_bytes))).unwrap();
        assert_eq!(rec_bytes, [0xBB; 16]);

        // 4. Third write ping-pongs back to region 0 (sequence 3).
        let region = fake::wait_for_future_ready(Box::pin(region.write_updated(
            1,
            CERT_MODEL_ALIAS_CERT,
            &[0x33; 48],
            &[0xCC; 16],
        )))
        .unwrap();
        assert_eq!(region.active_region(), Some(0));
        let mut recovered = chain(SpdmPalAsymAlgo::EccP384, 0);
        fake::wait_for_future_ready(Box::pin(recovered.load())).unwrap();
        assert_eq!(recovered.active_region(), Some(0));
        fake::wait_for_future_ready(Box::pin(recovered.read(0, &mut rec_bytes))).unwrap();
        assert_eq!(rec_bytes, [0xCC; 16]);
    }
}
