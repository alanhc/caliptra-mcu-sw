// Licensed under the Apache-2.0 license

//! Cert slot and endorsement chain types.
//!
//! Each certificate slot is represented by a [`CertSlot`] which holds slot
//! endorsement state and per-slot metadata. The backing storage is an
//! enum ([`SlotEndorsement`]) dispatching to `ReadOnly` (Vendor) or a
//! monomorphized [`ManagedEndorsementBackend`] implementation (Owner/Tenant)
//! without dynamic dispatch or heap allocation.

use crate::{CertificateAlgorithm, EndorsementRole};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use mcu_error::McuResult;

/// Number of cert slots managed by the store.
pub const NUM_CERT_SLOTS: usize = 3;

/// Default KeyUsageMask for Caliptra certificate slots.
pub const DEFAULT_KEY_USAGE_MASK: u16 = 0x0003;

/// Map internal cert slot index to [`EndorsementRole`].
pub const fn endorsement_role(index: usize) -> Option<EndorsementRole> {
    EndorsementRole::from_index(index)
}

/// Number of asymmetric algorithms a slot can hold a chain for.
pub const NUM_ASYM_ALGOS: usize = 2;

/// Supported certificate model in Caliptra (AliasCert).
pub const CERT_MODEL_ALIAS_CERT: u8 = 2;

/// Index into per-algorithm arrays.
pub const fn algo_index(algo: CertificateAlgorithm) -> usize {
    algo.index()
}

/// Maximum number of concurrent read regions tracked per `(role, algorithm)`
/// slot (supports both single-region and A/B double-buffered backends).
pub const MANAGED_REGION_COUNT: usize = 2;

/// Lightweight `Copy` read handle returned by [`ManagedEndorsementBackend::read_snapshot`]
/// so async endorsement reads do not hold a borrow of [`CertSlot`] across `.await`.
pub trait ManagedReadHandle: Copy {
    /// Logical region index (`0..MANAGED_REGION_COUNT`) being read.
    ///
    /// Single-region backends use the default (`0`). Double-buffered A/B
    /// backends return the active region index (`0` or `1`).
    fn active_region(&self) -> u8 {
        0
    }

    /// Read up to `buf.len()` bytes of the committed DER endorsement chain
    /// starting at `offset`.
    async fn read(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize>;
}

/// Pluggable storage backend for a single managed `(role, algorithm)`
/// endorsement chain.
///
/// Implementations are `Copy` value types stored statically inside
/// [`SharedCertStore`](crate::store::SharedCertStore) and monomorphized
/// without `dyn` dispatch or heap allocation.
pub trait ManagedEndorsementBackend: Copy + 'static {
    /// Lightweight `Copy` handle used to read the active endorsement across `.await`.
    type ReadHandle: ManagedReadHandle;

    /// Asymmetric algorithm this backend instance serves.
    fn algo(&self) -> CertificateAlgorithm;

    /// Whether a valid committed endorsement is currently present.
    fn is_initialized(&self) -> bool;

    /// Maximum DER endorsement byte length this backend can store.
    fn der_capacity(&self) -> usize;

    /// Byte length of the currently committed DER endorsement chain.
    fn size(&self) -> McuResult<usize>;

    /// Copy the 48-byte SHA-384 root certificate hash of the committed chain into `out`.
    fn root_cert_hash(&self, out: &mut [u8]) -> McuResult<()>;

    /// Logical `KeyPairID` bound to the committed endorsement, if initialized.
    fn key_pair_id(&self) -> Option<u8>;

    /// Certificate model (`CertInfo`) of the committed endorsement, if initialized.
    fn cert_info(&self) -> Option<u8>;

    /// `KeyUsageMask` of the committed endorsement, if initialized.
    fn key_usage_mask(&self) -> Option<u16> {
        self.is_initialized().then_some(DEFAULT_KEY_USAGE_MASK)
    }

    /// Logical region index (`0..MANAGED_REGION_COUNT`) that the next update
    /// will overwrite, or `None` if updates never overwrite an in-flight read region.
    ///
    /// Single-region backends default to `Some(0)`. Double-buffered A/B
    /// backends return `Some(staging_region)`.
    fn staging_region(&self) -> Option<u8> {
        Some(0)
    }

    /// Capture a lightweight read handle for the currently active endorsement.
    fn read_snapshot(&self) -> McuResult<Self::ReadHandle>;

    /// Clear in-memory initialized state so the endorsement is no longer advertised.
    fn discard(&mut self);

    /// Abort an in-progress streaming update without disturbing the active endorsement.
    fn abort_stream_update(&mut self);

    /// Prepare storage to receive a streamed endorsement of `data_len` bytes.
    async fn begin_stream_update(
        self,
        key_pair_id: u8,
        cert_info: u8,
        data_len: usize,
    ) -> McuResult<Self>;

    /// Write a chunk of streamed DER endorsement bytes at `offset`.
    async fn write_stream_chunk(&self, offset: usize, data: &[u8]) -> McuResult<()>;

    /// Read back a chunk of staged DER endorsement bytes at `offset` for verification.
    async fn read_stream_chunk(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize>;

    /// Commit a streamed endorsement after root-hash verification succeeds.
    async fn finish_stream_update(
        self,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data_len: usize,
    ) -> McuResult<Self>;

    /// Atomically write and commit a complete endorsement chain in one shot.
    async fn write_updated(
        self,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: &[u8; 48],
        data: &[u8],
    ) -> McuResult<Self>;

    /// Durably erase the endorsement from persistent storage.
    async fn erase_updated(self) -> McuResult<Self>;
}

/// Uninhabited placeholder backend for stores that do not configure managed storage.
///
/// Because `NoManagedEndorsement` has no variants, `SlotEndorsement::Managed`
/// is statically uninhabited when `B = NoManagedEndorsement`, allowing the
/// compiler to eliminate all managed-slot branches in read-only builds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoManagedEndorsement {}

impl ManagedReadHandle for NoManagedEndorsement {
    fn active_region(&self) -> u8 {
        match *self {}
    }

    async fn read(&self, _offset: usize, _buf: &mut [u8]) -> McuResult<usize> {
        match *self {}
    }
}

impl ManagedEndorsementBackend for NoManagedEndorsement {
    type ReadHandle = Self;

    fn algo(&self) -> CertificateAlgorithm {
        match *self {}
    }

    fn is_initialized(&self) -> bool {
        match *self {}
    }

    fn der_capacity(&self) -> usize {
        match *self {}
    }

    fn size(&self) -> McuResult<usize> {
        match *self {}
    }

    fn root_cert_hash(&self, _out: &mut [u8]) -> McuResult<()> {
        match *self {}
    }

    fn key_pair_id(&self) -> Option<u8> {
        match *self {}
    }

    fn cert_info(&self) -> Option<u8> {
        match *self {}
    }

    fn read_snapshot(&self) -> McuResult<Self::ReadHandle> {
        match *self {}
    }

    fn discard(&mut self) {
        match *self {}
    }

    fn abort_stream_update(&mut self) {
        match *self {}
    }

    async fn begin_stream_update(
        self,
        _key_pair_id: u8,
        _cert_info: u8,
        _data_len: usize,
    ) -> McuResult<Self> {
        match self {}
    }

    async fn write_stream_chunk(&self, _offset: usize, _data: &[u8]) -> McuResult<()> {
        match *self {}
    }

    async fn read_stream_chunk(&self, _offset: usize, _buf: &mut [u8]) -> McuResult<usize> {
        match *self {}
    }

    async fn finish_stream_update(
        self,
        _key_pair_id: u8,
        _cert_info: u8,
        _root_hash: &[u8; 48],
        _data_len: usize,
    ) -> McuResult<Self> {
        match self {}
    }

    async fn write_updated(
        self,
        _key_pair_id: u8,
        _cert_info: u8,
        _root_hash: &[u8; 48],
        _data: &[u8],
    ) -> McuResult<Self> {
        match self {}
    }

    async fn erase_updated(self) -> McuResult<Self> {
        match self {}
    }
}

/// Per-algorithm concurrency and generation state within a [`CertSlot`].
struct AlgoSlotState {
    /// State lock held high while an async write or erase is in progress
    /// for this algorithm.
    write_in_progress: AtomicBool,
    /// Monotonic generation counter incremented whenever this algorithm's
    /// endorsement is configured, published, or removed.
    generation_counter: AtomicU32,
    /// Count of in-flight async readers per region so an active region
    /// cannot be reclaimed/erased while a reader is suspended at `.await`.
    region_readers: [AtomicU32; MANAGED_REGION_COUNT],
}

impl AlgoSlotState {
    const fn new() -> Self {
        Self {
            write_in_progress: AtomicBool::new(false),
            generation_counter: AtomicU32::new(0),
            region_readers: [const { AtomicU32::new(0) }; MANAGED_REGION_COUNT],
        }
    }
}

/// A single certificate slot.
///
/// Slots store the endorsement/root portion. The store composes the full
/// cert chain by appending the DPE device chain and DPE leaf cert.
///
/// Identity and certificate model are shared by the slot. Certificate
/// availability and concurrency state remain per algorithm.
pub struct CertSlot<B: ManagedEndorsementBackend = NoManagedEndorsement> {
    /// Slot certificate-chain backing storage.
    pub endorsement: SlotEndorsement<B>,
    /// Immutable logical device-key binding shared by both algorithms.
    key_pair_id: Option<u8>,
    /// Per-algorithm write lock, generation counter, and active-region reader counts.
    algo_state: [AlgoSlotState; NUM_ASYM_ALGOS],
}

impl<B: ManagedEndorsementBackend> CertSlot<B> {
    pub const fn empty(key_pair_id: Option<u8>) -> Self {
        Self {
            endorsement: SlotEndorsement::Empty,
            key_pair_id,
            algo_state: [const { AlgoSlotState::new() }; NUM_ASYM_ALGOS],
        }
    }

    #[inline]
    fn state(&self, algo: CertificateAlgorithm) -> &AlgoSlotState {
        &self.algo_state[algo_index(algo)]
    }

    pub fn is_supported(&self) -> bool {
        self.endorsement.is_supported()
    }

    pub fn is_writable(&self) -> bool {
        self.endorsement.is_writable()
    }

    /// Whether this slot can serve a cert chain for `algo` right now.
    pub fn is_provisioned(&self, algo: CertificateAlgorithm) -> bool {
        self.endorsement.is_provisioned(algo)
    }

    pub fn write_in_progress(&self, algo: CertificateAlgorithm) -> bool {
        self.state(algo).write_in_progress.load(Ordering::Relaxed)
    }

    pub fn set_write_in_progress(&self, algo: CertificateAlgorithm, value: bool) {
        self.state(algo)
            .write_in_progress
            .store(value, Ordering::Relaxed);
    }

    pub fn generation_counter(&self, algo: CertificateAlgorithm) -> u32 {
        self.state(algo).generation_counter.load(Ordering::Relaxed)
    }

    pub(crate) fn bump_generation_counter(&self, algo: CertificateAlgorithm) {
        let counter = &self.state(algo).generation_counter;
        let next = counter.load(Ordering::Relaxed).wrapping_add(1);
        counter.store(next, Ordering::Relaxed);
    }

    pub(crate) fn acquire_region_reader(&self, algo: CertificateAlgorithm, region: u8) {
        let r = (region as usize) % MANAGED_REGION_COUNT;
        let readers = &self.state(algo).region_readers[r];
        let next = readers.load(Ordering::Relaxed).saturating_add(1);
        readers.store(next, Ordering::Relaxed);
    }

    pub(crate) fn release_region_reader(&self, algo: CertificateAlgorithm, region: u8) {
        let r = (region as usize) % MANAGED_REGION_COUNT;
        let readers = &self.state(algo).region_readers[r];
        let next = readers.load(Ordering::Relaxed).saturating_sub(1);
        readers.store(next, Ordering::Relaxed);
    }

    #[cfg(any(test, feature = "set-certificate"))]
    pub(crate) fn region_has_readers(&self, algo: CertificateAlgorithm, region: u8) -> bool {
        let r = (region as usize) % MANAGED_REGION_COUNT;
        self.state(algo).region_readers[r].load(Ordering::Relaxed) > 0
    }

    #[cfg(any(test, feature = "set-certificate"))]
    pub(crate) fn any_region_has_readers(&self, algo: CertificateAlgorithm) -> bool {
        self.state(algo)
            .region_readers
            .iter()
            .any(|count| count.load(Ordering::Relaxed) > 0)
    }

    pub fn key_pair_id(&self, algo: CertificateAlgorithm) -> Option<u8> {
        if !self.is_provisioned(algo) {
            return None;
        }
        match &self.endorsement {
            SlotEndorsement::ReadOnly(_) => self.key_pair_id,
            SlotEndorsement::Managed(m) => m.get_endorsement(algo)?.key_pair_id(),
            SlotEndorsement::Empty => None,
        }
    }

    pub(crate) fn configured_key_pair_id(&self) -> Option<u8> {
        self.key_pair_id
    }

    pub fn cert_info(&self, algo: CertificateAlgorithm) -> Option<u8> {
        if !self.is_provisioned(algo) {
            return None;
        }
        match &self.endorsement {
            SlotEndorsement::ReadOnly(_) => Some(CERT_MODEL_ALIAS_CERT),
            SlotEndorsement::Managed(m) => m.get_endorsement(algo)?.cert_info(),
            SlotEndorsement::Empty => None,
        }
    }

    pub fn key_usage_mask(&self, algo: CertificateAlgorithm) -> Option<u16> {
        if !self.is_provisioned(algo) {
            return None;
        }
        match &self.endorsement {
            SlotEndorsement::Managed(m) => m.get_endorsement(algo)?.key_usage_mask(),
            _ => Some(DEFAULT_KEY_USAGE_MASK),
        }
    }
}

/// Per-slot endorsement cert chain — enum dispatch.
pub enum SlotEndorsement<B: ManagedEndorsementBackend = NoManagedEndorsement> {
    /// Not provisioned and not exposed as a supported slot.
    Empty,
    /// Read-only endorsement backed by static root CA certs (slot 0).
    ReadOnly(ReadOnlyEndorsementSlot),
    /// Managed endorsement/root chains backed by a platform storage backend
    /// (slots 1-2), one independent backend instance per algorithm.
    Managed(ManagedEndorsementSlot<B>),
}

impl<B: ManagedEndorsementBackend> SlotEndorsement<B> {
    pub fn root_cert_hash(&self, algo: CertificateAlgorithm, out: &mut [u8]) -> McuResult<()> {
        match self {
            Self::ReadOnly(e) => e.root_cert_hash(algo, out),
            Self::Managed(m) => m
                .get_endorsement(algo)
                .ok_or(mcu_error::codes::INVARIANT)?
                .root_cert_hash(out),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn size(&self, algo: CertificateAlgorithm) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.size(algo),
            Self::Managed(m) => m
                .get_endorsement(algo)
                .ok_or(mcu_error::codes::INVARIANT)?
                .size(),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn capacity(&self, algo: CertificateAlgorithm) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.size(algo),
            Self::Managed(m) => Ok(m
                .get_endorsement(algo)
                .ok_or(mcu_error::codes::INVARIANT)?
                .der_capacity()),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub(crate) fn active_region(&self, algo: CertificateAlgorithm) -> McuResult<Option<u8>> {
        match self {
            Self::ReadOnly(e) => {
                let _ = e.get_endorsement(algo).ok_or(mcu_error::codes::INVARIANT)?;
                Ok(None)
            }
            Self::Managed(m) => Ok(Some(
                m.get_endorsement(algo)
                    .ok_or(mcu_error::codes::INVARIANT)?
                    .read_snapshot()?
                    .active_region(),
            )),
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub async fn read(
        &self,
        algo: CertificateAlgorithm,
        offset: usize,
        buf: &mut [u8],
    ) -> McuResult<usize> {
        match self {
            Self::ReadOnly(e) => e.read(algo, offset, buf),
            Self::Managed(m) => {
                let snapshot = m
                    .get_endorsement(algo)
                    .ok_or(mcu_error::codes::INVARIANT)?
                    .read_snapshot()?;
                snapshot.read(offset, buf).await
            }
            Self::Empty => Err(mcu_error::codes::INVARIANT),
        }
    }

    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Empty)
    }

    pub fn is_writable(&self) -> bool {
        #[cfg(feature = "set-certificate")]
        {
            matches!(self, Self::Managed(_))
        }
        #[cfg(not(feature = "set-certificate"))]
        {
            false
        }
    }

    pub fn is_provisioned(&self, algo: CertificateAlgorithm) -> bool {
        match self {
            Self::ReadOnly(e) => e.get_endorsement(algo).is_some(),
            Self::Managed(m) => m.get_endorsement(algo).is_some_and(|r| r.is_initialized()),
            Self::Empty => false,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SingleEndorsementChain {
    pub root_cert_hash: [u8; 48],
    pub chain: &'static [&'static [u8]],
    pub chain_len: usize,
}

impl SingleEndorsementChain {
    pub fn new(chain: &'static [&'static [u8]], root_cert_hash: [u8; 48]) -> Self {
        let chain_len = chain.iter().map(|c| c.len()).sum();
        Self {
            root_cert_hash,
            chain,
            chain_len,
        }
    }

    pub fn read(&self, offset: usize, buf: &mut [u8]) -> usize {
        let mut cert_offset = offset;
        let mut pos = 0;
        for cert in self.chain.iter() {
            if cert_offset < cert.len() {
                let len = cert
                    .len()
                    .saturating_sub(cert_offset)
                    .min(buf.len().saturating_sub(pos));
                if let (Some(dst), Some(src)) = (
                    buf.get_mut(pos..pos + len),
                    cert.get(cert_offset..cert_offset + len),
                ) {
                    for (d, s) in dst.iter_mut().zip(src) {
                        *d = *s;
                    }
                }
                pos += len;
                cert_offset = 0;
                if pos == buf.len() {
                    break;
                }
            } else {
                cert_offset -= cert.len();
            }
        }
        pos
    }
}

/// Read-only endorsement — static root CA cert chain for ECC and optional ML-DSA.
pub struct ReadOnlyEndorsementSlot {
    ecc: SingleEndorsementChain,
    mldsa: Option<SingleEndorsementChain>,
}

impl ReadOnlyEndorsementSlot {
    pub fn new(chain: &'static [&'static [u8]], root_cert_hash: [u8; 48]) -> Self {
        Self {
            ecc: SingleEndorsementChain::new(chain, root_cert_hash),
            mldsa: None,
        }
    }

    pub fn with_mldsa(mut self, chain: &'static [&'static [u8]], root_cert_hash: [u8; 48]) -> Self {
        self.mldsa = Some(SingleEndorsementChain::new(chain, root_cert_hash));
        self
    }

    pub fn get_endorsement(&self, algo: CertificateAlgorithm) -> Option<&SingleEndorsementChain> {
        match algo {
            CertificateAlgorithm::EccP384 => Some(&self.ecc),
            CertificateAlgorithm::MlDsa87 => self.mldsa.as_ref(),
        }
    }

    pub fn read(
        &self,
        algo: CertificateAlgorithm,
        offset: usize,
        buf: &mut [u8],
    ) -> McuResult<usize> {
        let chain = self
            .get_endorsement(algo)
            .ok_or(mcu_error::codes::INVARIANT)?;
        Ok(chain.read(offset, buf))
    }

    fn root_cert_hash(&self, algo: CertificateAlgorithm, out: &mut [u8]) -> McuResult<()> {
        let chain = self
            .get_endorsement(algo)
            .ok_or(mcu_error::codes::INVARIANT)?;
        for (d, s) in out.iter_mut().zip(&chain.root_cert_hash) {
            *d = *s;
        }
        Ok(())
    }

    fn size(&self, algo: CertificateAlgorithm) -> McuResult<usize> {
        let chain = self
            .get_endorsement(algo)
            .ok_or(mcu_error::codes::INVARIANT)?;
        Ok(chain.chain_len)
    }
}

/// The managed backend instances backing one certificate slot.
///
/// ECC is mandatory — a managed slot always has a backend for the
/// classical chain — while ML-DSA is optional so that a platform which
/// has not allocated PQC storage still builds and runs. A slot with
/// no ML-DSA backend simply reports itself unprovisioned for ML-DSA.
#[derive(Clone, Copy)]
pub struct ManagedEndorsementSlot<B: ManagedEndorsementBackend = NoManagedEndorsement> {
    ecc: B,
    mldsa: Option<B>,
}

impl<B: ManagedEndorsementBackend> ManagedEndorsementSlot<B> {
    pub fn new(ecc: B) -> Self {
        debug_assert!(matches!(ecc.algo(), CertificateAlgorithm::EccP384));
        Self { ecc, mldsa: None }
    }

    pub fn with_mldsa(mut self, mldsa: B) -> Self {
        debug_assert!(matches!(mldsa.algo(), CertificateAlgorithm::MlDsa87));
        self.mldsa = Some(mldsa);
        self
    }

    /// The endorsement backend serving `algo`, or `None` if this slot has none.
    pub fn get_endorsement(&self, algo: CertificateAlgorithm) -> Option<&B> {
        match algo {
            CertificateAlgorithm::EccP384 => Some(&self.ecc),
            CertificateAlgorithm::MlDsa87 => self.mldsa.as_ref(),
        }
    }

    /// Install an updated endorsement backend, routed by its [`ManagedEndorsementBackend::algo`].
    pub fn set_endorsement(&mut self, endorsement: B) {
        match endorsement.algo() {
            CertificateAlgorithm::EccP384 => self.ecc = endorsement,
            CertificateAlgorithm::MlDsa87 => self.mldsa = Some(endorsement),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct DummyBackend {
        algo: CertificateAlgorithm,
        initialized: bool,
        len: usize,
        key_pair_id: u8,
        cert_info: u8,
        root_hash: [u8; 48],
    }

    impl DummyBackend {
        const fn new(algo: CertificateAlgorithm) -> Self {
            Self {
                algo,
                initialized: false,
                len: 0,
                key_pair_id: 1,
                cert_info: CERT_MODEL_ALIAS_CERT,
                root_hash: [0x42; 48],
            }
        }
    }

    impl ManagedReadHandle for DummyBackend {
        async fn read(&self, offset: usize, buf: &mut [u8]) -> McuResult<usize> {
            if offset >= self.len || buf.is_empty() {
                return Ok(0);
            }
            let n = (self.len - offset).min(buf.len());
            buf[..n].fill(0xAA);
            Ok(n)
        }
    }

    impl ManagedEndorsementBackend for DummyBackend {
        type ReadHandle = Self;

        fn algo(&self) -> CertificateAlgorithm {
            self.algo
        }

        fn is_initialized(&self) -> bool {
            self.initialized
        }

        fn der_capacity(&self) -> usize {
            4096
        }

        fn size(&self) -> McuResult<usize> {
            self.initialized
                .then_some(self.len)
                .ok_or(mcu_error::codes::INVARIANT)
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

        fn read_snapshot(&self) -> McuResult<Self::ReadHandle> {
            self.initialized
                .then_some(*self)
                .ok_or(mcu_error::codes::INVARIANT)
        }

        fn discard(&mut self) {
            self.initialized = false;
            self.len = 0;
        }

        fn abort_stream_update(&mut self) {}

        async fn begin_stream_update(
            self,
            _key_pair_id: u8,
            _cert_info: u8,
            _data_len: usize,
        ) -> McuResult<Self> {
            Ok(self)
        }

        async fn write_stream_chunk(&self, _offset: usize, _data: &[u8]) -> McuResult<()> {
            Ok(())
        }

        async fn read_stream_chunk(&self, _offset: usize, _buf: &mut [u8]) -> McuResult<usize> {
            Ok(0)
        }

        async fn finish_stream_update(
            mut self,
            key_pair_id: u8,
            cert_info: u8,
            root_hash: &[u8; 48],
            data_len: usize,
        ) -> McuResult<Self> {
            self.initialized = true;
            self.key_pair_id = key_pair_id;
            self.cert_info = cert_info;
            self.root_hash = *root_hash;
            self.len = data_len;
            Ok(self)
        }

        async fn write_updated(
            mut self,
            key_pair_id: u8,
            cert_info: u8,
            root_hash: &[u8; 48],
            data: &[u8],
        ) -> McuResult<Self> {
            self.initialized = true;
            self.key_pair_id = key_pair_id;
            self.cert_info = cert_info;
            self.root_hash = *root_hash;
            self.len = data.len();
            Ok(self)
        }

        async fn erase_updated(mut self) -> McuResult<Self> {
            self.discard();
            Ok(self)
        }
    }

    #[test]
    fn managed_regions_are_provisioned_independently() {
        let mut ecc = DummyBackend::new(CertificateAlgorithm::EccP384);
        let mldsa = DummyBackend::new(CertificateAlgorithm::MlDsa87);

        let slot = ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa);
        assert!(!SlotEndorsement::Managed(slot).is_provisioned(CertificateAlgorithm::EccP384));
        assert!(!SlotEndorsement::Managed(slot).is_provisioned(CertificateAlgorithm::MlDsa87));

        ecc.initialized = true;
        let slot = ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa);
        let endorsement = SlotEndorsement::Managed(slot);
        assert!(endorsement.is_provisioned(CertificateAlgorithm::EccP384));
        assert!(!endorsement.is_provisioned(CertificateAlgorithm::MlDsa87));

        let mut mldsa = mldsa;
        mldsa.initialized = true;
        let endorsement =
            SlotEndorsement::Managed(ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa));
        assert!(endorsement.is_provisioned(CertificateAlgorithm::EccP384));
        assert!(endorsement.is_provisioned(CertificateAlgorithm::MlDsa87));
    }

    #[test]
    fn managed_slot_without_mldsa_region_fails_closed() {
        let mut ecc = DummyBackend::new(CertificateAlgorithm::EccP384);
        ecc.initialized = true;
        ecc.len = 64;
        let endorsement = SlotEndorsement::Managed(ManagedEndorsementSlot::new(ecc));

        assert!(endorsement.is_provisioned(CertificateAlgorithm::EccP384));
        assert!(!endorsement.is_provisioned(CertificateAlgorithm::MlDsa87));

        assert!(endorsement.size(CertificateAlgorithm::EccP384).is_ok());
        assert!(endorsement.size(CertificateAlgorithm::MlDsa87).is_err());

        let mut out = [0u8; 48];
        assert!(endorsement
            .root_cert_hash(CertificateAlgorithm::EccP384, &mut out)
            .is_ok());
        assert!(endorsement
            .root_cert_hash(CertificateAlgorithm::MlDsa87, &mut out)
            .is_err());
    }

    #[test]
    fn set_endorsement_routes_by_algorithm() {
        let ecc = DummyBackend::new(CertificateAlgorithm::EccP384);
        let mldsa = DummyBackend::new(CertificateAlgorithm::MlDsa87);
        let mut slot = ManagedEndorsementSlot::new(ecc).with_mldsa(mldsa);

        let mut updated = mldsa;
        updated.initialized = true;
        updated.len = 128;
        slot.set_endorsement(updated);

        assert!(!slot
            .get_endorsement(CertificateAlgorithm::EccP384)
            .unwrap()
            .is_initialized());
        assert_eq!(
            slot.get_endorsement(CertificateAlgorithm::MlDsa87)
                .unwrap()
                .size(),
            Ok(128)
        );
    }
}

#[cfg(test)]
mod algo_tests {
    use super::*;

    const ECC_CHAIN: &[&[u8]] = &[&[0x30, 0x01, 0x00]];
    const MLDSA_CHAIN: &[&[u8]] = &[&[0x30, 0x02, 0x00, 0x00]];

    #[test]
    fn read_only_slot_is_unprovisioned_for_missing_algorithm() {
        let ecc_only: SlotEndorsement =
            SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(ECC_CHAIN, [0u8; 48]));
        assert!(ecc_only.is_provisioned(CertificateAlgorithm::EccP384));
        // Without an ML-DSA chain the slot must not be advertised in an
        // ML-DSA connection: otherwise GET_CERTIFICATE would serve the
        // ECC chain against an ML-DSA negotiation.
        assert!(!ecc_only.is_provisioned(CertificateAlgorithm::MlDsa87));

        let both: SlotEndorsement = SlotEndorsement::ReadOnly(
            ReadOnlyEndorsementSlot::new(ECC_CHAIN, [0u8; 48]).with_mldsa(MLDSA_CHAIN, [1u8; 48]),
        );
        assert!(both.is_provisioned(CertificateAlgorithm::EccP384));
        assert!(both.is_provisioned(CertificateAlgorithm::MlDsa87));
    }

    #[test]
    fn empty_slot_is_never_provisioned() {
        let empty: SlotEndorsement = SlotEndorsement::Empty;
        assert!(!empty.is_provisioned(CertificateAlgorithm::EccP384));
        assert!(!empty.is_provisioned(CertificateAlgorithm::MlDsa87));
    }

    #[test]
    fn cert_slot_metadata_consistency_and_write_lock() {
        let mut slot: CertSlot = CertSlot::empty(Some(1));
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::EccP384), None);
        assert_eq!(slot.cert_info(CertificateAlgorithm::EccP384), None);

        // Provision a read-only slot for both algorithms.
        slot.endorsement = SlotEndorsement::ReadOnly(
            ReadOnlyEndorsementSlot::new(ECC_CHAIN, [0u8; 48]).with_mldsa(MLDSA_CHAIN, [1u8; 48]),
        );

        // Both algorithms expose the configured identity when provisioned.
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::EccP384), Some(1));
        assert_eq!(
            slot.cert_info(CertificateAlgorithm::EccP384),
            Some(CERT_MODEL_ALIAS_CERT)
        );
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::MlDsa87), Some(1));
        assert_eq!(
            slot.cert_info(CertificateAlgorithm::MlDsa87),
            Some(CERT_MODEL_ALIAS_CERT)
        );

        // When a write is in progress for ECC, the writer lock is active for ECC only,
        // while active-region metadata remains readable for both algorithms.
        slot.set_write_in_progress(CertificateAlgorithm::EccP384, true);
        assert!(slot.write_in_progress(CertificateAlgorithm::EccP384));
        assert!(!slot.write_in_progress(CertificateAlgorithm::MlDsa87));
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::EccP384), Some(1));
        assert_eq!(
            slot.cert_info(CertificateAlgorithm::EccP384),
            Some(CERT_MODEL_ALIAS_CERT)
        );
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::MlDsa87), Some(1));
        assert_eq!(
            slot.cert_info(CertificateAlgorithm::MlDsa87),
            Some(CERT_MODEL_ALIAS_CERT)
        );

        slot.set_write_in_progress(CertificateAlgorithm::EccP384, false);
        assert!(!slot.write_in_progress(CertificateAlgorithm::EccP384));
    }

    #[test]
    fn configured_identity_is_hidden_for_an_absent_algorithm() {
        let mut slot: CertSlot = CertSlot::empty(Some(1));
        slot.endorsement =
            SlotEndorsement::ReadOnly(ReadOnlyEndorsementSlot::new(ECC_CHAIN, [0; 48]));
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::EccP384), Some(1));
        assert_eq!(slot.key_pair_id(CertificateAlgorithm::MlDsa87), None);
        assert_eq!(slot.cert_info(CertificateAlgorithm::MlDsa87), None);
    }
}
