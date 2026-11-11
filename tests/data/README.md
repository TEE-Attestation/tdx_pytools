# Test fixtures

## `intel_tdx_sample/`

Intel's sample TDX quote and matching collateral from the
[Intel SGX/TDX DCAP Quote Verification Library](https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary)
(`Src/AttestationApp/sampleData/tdx/`, commit `89c589f2`, BSD-3-Clause — see
`LICENSE.txt` in that directory). Files are unmodified.

| File | Purpose |
|---|---|
| `quote.dat` | TDX v4 quote, ECDSA-P256, QE certification data type 5 with a **DER** PCK chain |
| `pckCert.pem`, `pckSignChain.pem` | PCK leaf and signing chain |
| `tcbInfo.json`, `tcbSignChain.pem` | TCB Info and its signing chain |
| `qeIdentity.json` | QE Identity |
| `rootCaCrl.der`, `intermediateCaCrl.der` | CRLs |
| `trustedRootCaCert.pem` | Intel SGX Root CA |

The quote is a structural sample: every TD measurement (`mr_td`, `rtmr0`–`3`,
`mr_config_id`, …) and `report_data` are all-zero, while `tee_tcb_svn`, the QE
vendor id and the QE report fields are populated. Values asserted in
`tests/test_policy.py` are pinned from this file in its `_fixture_values`
fixture.
