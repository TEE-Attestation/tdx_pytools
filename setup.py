# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Setup configuration for tdx_pytools package.

from setuptools import find_packages, setup

setup(
    name="tdx_pytools",
    version="0.1.1",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "cryptography>=39.0.0",
        "pyasn1>=0.4.8",
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "tdx-print=tdx_pytools.print_quote:main",
            "tdx-verify=tdx_pytools.verify:main",
        ],
    },
    description="Python tools for Intel SGX/TDX attestation",
    url="https://github.com/TEE-Attestation/tdx_pytools",
    author="Isaac Matthews",
    author_email="isaac@hpe.com",
    license="MIT",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
)
