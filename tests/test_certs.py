# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Tests for QE certification data parsing in tdx_pytools.certs.

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tdx_pytools import Quote
from tdx_pytools.certs import PCKCertChain

INTEL_SAMPLE = Path(__file__).parent / "data" / "intel_tdx_sample"


@pytest.fixture(scope="module")
def intel_quote() -> Quote:
    return Quote.unpack((INTEL_SAMPLE / "quote.dat").read_bytes())


@pytest.fixture(scope="module")
def pck_chain_pems() -> list:
    """The three certificates Intel ships as PEM alongside the quote."""
    leaf = (INTEL_SAMPLE / "pckCert.pem").read_bytes()
    chain = (INTEL_SAMPLE / "pckSignChain.pem").read_bytes()
    return x509.load_pem_x509_certificates(leaf + chain)


class TestPckCertChainFromCertificationData:
    def test_der_chain_parses(self, intel_quote):
        """Intel's sample embeds the PCK chain as concatenated DER, not PEM.

        Regression test: the parser assumed PEM and rejected this quote with
        a MalformedFraming error.
        """
        chain = intel_quote.signature_data.qe_cert_data.pck_cert_chain
        assert chain is not None
        assert chain.pck_cert is not None
        assert len(chain.cert_chain) == 2

    def test_der_chain_matches_shipped_pem_files(self, intel_quote, pck_chain_pems):
        """The embedded DER chain is the same set of certs Intel ships as PEM."""
        chain = intel_quote.signature_data.qe_cert_data.pck_cert_chain
        embedded = {
            c.fingerprint(c.signature_hash_algorithm) for c in chain.certificates
        }
        shipped = {c.fingerprint(c.signature_hash_algorithm) for c in pck_chain_pems}
        assert embedded == shipped

    def test_leaf_is_the_pck_certificate(self, intel_quote):
        """Intel's sample embeds the chain root-first; the leaf must still be
        identified as the PCK certificate, not whichever cert came first.

        Regression test: the first certificate was taken as the leaf, so
        pck_cert was the Intel SGX Root CA.
        """
        chain = intel_quote.signature_data.qe_cert_data.pck_cert_chain
        cn = chain.pck_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        assert cn[0].value == "Intel SGX PCK Certificate"
        root_cn = chain.cert_chain[-1].subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )
        assert root_cn[0].value == "Intel SGX Root CA"
        assert chain.cert_chain[-1].issuer == chain.cert_chain[-1].subject

    def test_chain_is_ordered_leaf_to_root(self, intel_quote):
        certs = intel_quote.signature_data.qe_cert_data.pck_cert_chain.certificates
        for child, parent in zip(certs, certs[1:]):
            assert child.issuer == parent.subject

    @pytest.mark.parametrize("order", ["leaf_first", "root_first", "shuffled"])
    def test_any_input_order_normalised(self, pck_chain_pems, order):
        # pck_chain_pems is [leaf, root, intermediate] as shipped.
        leaf, root, inter = pck_chain_pems
        inputs = {
            "leaf_first": [leaf, inter, root],
            "root_first": [root, inter, leaf],
            "shuffled": [inter, leaf, root],
        }[order]
        pem = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in inputs)
        chain = PCKCertChain.from_certification_data(pem)
        assert chain.certificates == [leaf, inter, root]
        assert chain.verify_chain()

    def test_pem_chain_still_parses(self, pck_chain_pems):
        pem = b"".join(
            c.public_bytes(serialization.Encoding.PEM) for c in pck_chain_pems
        )
        chain = PCKCertChain.from_certification_data(pem)
        assert len(chain.cert_chain) == 2

    def test_pem_with_trailing_nul_padding_parses(self, pck_chain_pems):
        """Some quote generators NUL-pad the certification data."""
        pem = b"".join(
            c.public_bytes(serialization.Encoding.PEM) for c in pck_chain_pems
        )
        chain = PCKCertChain.from_certification_data(pem + b"\x00" * 7)
        assert len(chain.cert_chain) == 2

    def test_der_single_certificate(self, pck_chain_pems):
        der = pck_chain_pems[0].public_bytes(serialization.Encoding.DER)
        chain = PCKCertChain.from_certification_data(der)
        assert chain.pck_cert == pck_chain_pems[0]
        assert not chain.cert_chain

    def test_garbage_rejected(self):
        with pytest.raises(ValueError, match="neither PEM nor DER"):
            PCKCertChain.from_certification_data(b"\x01\x02\x03")

    def test_truncated_der_rejected(self, pck_chain_pems):
        der = pck_chain_pems[0].public_bytes(serialization.Encoding.DER)
        with pytest.raises(ValueError, match="Truncated DER"):
            PCKCertChain.from_certification_data(der[:-10])

    def test_empty_rejected(self):
        with pytest.raises(ValueError, match="No valid certificates"):
            PCKCertChain.from_certification_data(b"")
