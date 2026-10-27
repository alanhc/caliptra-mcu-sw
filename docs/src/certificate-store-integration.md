# Certificate Store Integration Guide

## Purpose

This guide walks platform integrators through configuring, initializing, and
connecting the Caliptra MCU certificate store (`caliptra-mcu-cert-store`).

For background and protocol specifications, see:

- [Caliptra Certificate Model](./certificate_model.md) — trust model, roles, algorithms, and chain layout.
- [Caliptra MCU Certificate Store](./cert_store.md) — architecture and design guarantees.
- [In-field Certificate Provisioning and Management](./certificate_provisioning.md) — Owner and Tenant provisioning flows.
- [External Mailbox Commands](./external_mailbox_cmds.md) — MCI certificate command payloads.

## Integration steps

1. [Step 1: Define the platform profile](#step-1-define-the-platform-profile)
2. [Step 2: Provide Vendor certificates](#step-2-provide-vendor-certificates)
3. [Step 3: Configure managed endorsement storage](#step-3-configure-managed-endorsement-storage)
4. [Step 4: Initialize the store at startup](#step-4-initialize-the-store-at-startup)
5. [Step 5: Connect transports and authorization](#step-5-connect-transports-and-authorization)
6. [Step 6: Validate the integration](#step-6-validate-the-integration)

---

## Step 1: Define the platform profile

Choose the static configuration for your platform before building the runtime:

| Setting | Options | Notes |
| --- | --- | --- |
| **Algorithms** | `ECC P-384` (mandatory)<br>`ML-DSA-87` (optional PQC) | When `ML-DSA-87` is enabled, each active slot maintains independent ECC P-384 and ML-DSA-87 chains. |
| **Slots** | `Vendor` (mandatory, read-only)<br>`Owner` (optional, managed)<br>`Tenant` (optional, managed) | `Vendor` is provisioned at manufacturing. `Owner` and `Tenant` can be updated in the field. |
| **PKI anchor point** | Fixed (`LDevID = 1`) or unpinned (`None`) | `Vendor` always anchors at `IDevID (0)`. By default, `Owner` pins `LDevID (1)` and `Tenant` is unpinned (caller must specify a supported nonzero key ID). |
| **Storage backend `B`** | `ManagedEndorsementBackend` implementation (defaults to `NoManagedEndorsement` when only `Vendor` is enabled) | Statically monomorphized via `SharedCertStore<B>`, `TaskCertStore<B>`, and `McuSpdmPal<M, B>`. |

> **Integrator responsibility**: The SDK enforces slot mutability, key-anchor policy, and storage capacity, but does **not** parse X.509 extensions or verify requester permissions. Integrators must validate certificate contents/extensions and enforce requester authorization.

---

## Step 2: Provide Vendor certificates

The `Vendor` slot is read-only for the lifetime of the device:

1. **Embed Vendor CA certificates**: Compile the Vendor Root CA (and any intermediate CA) DER bytes into the user application.
2. **Supply IDevID certificates at boot**: Retrieve the manufacturing-signed IDevID DER certificate for each enabled algorithm (from OTP or platform storage) and import it into Caliptra during startup.
3. Do not allocate writable storage for the `Vendor` slot.

---

## Step 3: Configure managed endorsement storage

*(Skip this step if only the read-only `Vendor` slot is enabled; `SharedCertStore::new()` defaults to `NoManagedEndorsement` with zero storage overhead.)*

When `Owner` or `Tenant` slots are enabled, allocate disjoint persistent storage for each `(role, algorithm)` pair and provide a `ManagedEndorsementBackend` implementation (`caliptra_mcu_cert_store::endorsement`):

- **`ManagedEndorsementBackend`** (`Copy + 'static`): Manages one `(role, algorithm)` endorsement store — metadata queries, `read_snapshot()`, single-shot/streamed updates, and durable erasure.
- **`ManagedReadHandle`** (`Copy + 'static`): Lightweight coordinates returned by `read_snapshot()` so async reads (`read(offset, buf)`) do not borrow `SharedCertStore` across `.await` points while active readers are tracked on `active_region()`.

For Tock `SpiFlash` partitions, integrators can reuse the reference A/B double-buffered implementation (`SingleManagedEndorsement` in `platforms/emulator/runtime/userspace/apps/user/src/cert_store/flash_endorsement.rs`), which writes updates to a `staging_region` while keeping the `active_region` readable and clears `staging_region` before `active_region` on erase. For other media (NAND, EEPROM, KV store, or host storage), implement the two traits directly.

---

## Step 4: Initialize the store at startup

Call `cert_store::init(...)` once before starting any responder tasks:

1. **Initialize Vendor**: Import IDevID certificates into Caliptra and register the static Vendor endorsement chains. Halt startup if the mandatory Vendor ECC P-384 chain fails.
2. **Recover managed slots**: For each enabled `(role, algorithm)` backend, load persisted state, validate it against the role's key-anchor policy, and register it via `SHARED_CERT_STORE.install_managed_backend(role, backend)`.
3. **Create per-task handles**: Construct a `TaskCertStore<B>` (`TaskCertStore::new(&SHARED_CERT_STORE)`) for each responder task so task-local caches remain isolated while sharing the global endorsement state.

---

## Step 5: Connect transports and authorization

All transports must wrap the same `&'static SharedCertStore<B>` so updates on one transport are immediately visible on all others:

- **SPDM responder**: Pass `TaskCertStore<B>` into `McuSpdmPal<M, B>` (`SpdmPalCertStore`). Maps SPDM SlotIDs (`0` = Vendor, `2` = Owner, `3` = Tenant) and negotiated algorithms to the shared store.
- **MCI mailbox responder**: Use a dedicated `TaskCertStore<B>` to service `MC_GET_CERT_CHAIN_INFO`, `MC_GET_CERT_CHAIN`, and `MC_SET_CERT_CHAIN` by `(EndorsementRole, CertificateAlgorithm)`.
- **Authorization gate**: Before invoking any write or erase method on `TaskCertStore<B>`, verify the requester's identity and permission to modify the target `(role, algorithm)` slot.

---

## Step 6: Validate the integration

Verify the following on target hardware or emulation:

- [ ] **Chain retrieval**: `GET_CERTIFICATE` (SPDM) and `MC_GET_CERT_CHAIN` (MCI) return complete chains from Root CA to DPE leaf for all provisioned slots.
- [ ] **Attestation binding**: SPDM `CHALLENGE` and `MC_GET_ATTESTATION` signatures verify against the retrieved leaf certificate.
- [ ] **Slot & algorithm isolation**: Updating or erasing `Owner` ECC P-384 does not affect `Owner` ML-DSA-87 or `Tenant` slots.
- [ ] **Atomic updates & power-loss safety**: Aborting a multi-chunk stream or resetting mid-update preserves the previous active endorsement.
- [ ] **Cross-transport visibility**: An endorsement provisioned via SPDM `SET_CERTIFICATE` is immediately reflected in `MC_GET_CERT_CHAIN_INFO` / `MC_GET_CERT_CHAIN` (and vice versa).
- [ ] **Policy & authorization**: Writes to `Vendor` (`role = 0`) and unauthorized writes to `Owner`/`Tenant` are rejected without altering state.
