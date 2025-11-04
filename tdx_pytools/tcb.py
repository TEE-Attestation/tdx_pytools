# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# TCB Info handling - TCB level matching and status evaluation for Intel TDX/SGX.

"""
TCB Info structure handling for Intel TDX/SGX attestation.

This module provides classes and enums for parsing and validating TCB Info
structures as defined in the Intel PCS API specification.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from . import tdx_logging

logger = tdx_logging.get_logger(__name__)


class TcbStatus(Enum):
    """TCB level status values as defined in the Intel PCS API specification."""

    # Status values for SGX/TDX platform TCB levels
    UP_TO_DATE = "UpToDate"
    SW_HARDENING_NEEDED = "SWHardeningNeeded"
    CONFIGURATION_NEEDED = "ConfigurationNeeded"
    CONFIGURATION_AND_SW_HARDENING_NEEDED = "ConfigurationAndSWHardeningNeeded"
    OUT_OF_DATE = "OutOfDate"
    OUT_OF_DATE_CONFIGURATION_NEEDED = "OutOfDateConfigurationNeeded"
    REVOKED = "Revoked"
    NOT_SUPPORTED = "NotSupported"

    @classmethod
    def from_string(cls, status_str: str) -> "TcbStatus":
        """
        Convert a string status value to TcbStatus enum.

        Args:
            status_str: String representation of TCB status

        Returns:
            TcbStatus enum value

        Raises:
            ValueError: If status string is not recognized
        """
        for status in cls:
            if status.value == status_str:
                return status
        raise ValueError(f"Unknown TCB status: {status_str}")

    def is_terminal(self) -> bool:
        """
        Check if this TCB status indicates a terminal state.

        Returns:
            bool: True if platform is terminal, False otherwise
        """
        return self not in (
            TcbStatus.UP_TO_DATE,
            TcbStatus.SW_HARDENING_NEEDED,
            TcbStatus.CONFIGURATION_NEEDED,
            TcbStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED,
            TcbStatus.OUT_OF_DATE,
            TcbStatus.OUT_OF_DATE_CONFIGURATION_NEEDED,
        )

    def compare_status(self, other: "TcbStatus") -> bool:
        """
        Compare this TCB status with another TCB status.

        Args:
            other: Another TcbStatus to compare against

        Returns:
            bool: True if self is better than or equal to other, False otherwise
        """
        priority_order = [
            TcbStatus.NOT_SUPPORTED,
            TcbStatus.REVOKED,
            TcbStatus.OUT_OF_DATE_CONFIGURATION_NEEDED,
            TcbStatus.OUT_OF_DATE,
            TcbStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED,
            TcbStatus.CONFIGURATION_NEEDED,
            TcbStatus.SW_HARDENING_NEEDED,
            TcbStatus.UP_TO_DATE,
        ]

        self_index = priority_order.index(self)
        other_index = priority_order.index(other)

        if self_index < other_index:
            return False  # self is worse
        else:
            return True  # self is better or equal


@dataclass
class Tcb:
    """
    Represents a Trusted Computing Base (TCB) evaluation result.

    This class encapsulates the TCB status, date, and associated advisory IDs
    from a TCB level evaluation.

    Attributes:
        status: The TCB status (e.g., UpToDate, OutOfDate, etc.)
        date: The TCB date indicating when this TCB level was published (optional)
        advisory_ids: List of security advisory IDs associated with this TCB level
    """

    status: TcbStatus
    date: Optional[str] = None
    advisory_ids: List[str] = None

    def __post_init__(self):
        """Initialize advisory_ids to empty list if None."""
        if self.advisory_ids is None:
            self.advisory_ids = []

    def is_trusted(self) -> bool:
        """
        Check if this TCB indicates a trusted platform.

        Returns:
            bool: True if the TCB status indicates the platform can be trusted
        """
        return self.status.is_trusted()

    def __str__(self) -> str:
        """String representation of the TCB."""
        advisory_str = (
            f", Advisory IDs: {', '.join(self.advisory_ids)}"
            if self.advisory_ids
            else ""
        )
        date_str = f", Date: {self.date}" if self.date else ""
        return f"TCB(Status: {self.status.value}{date_str}{advisory_str})"

    def __repr__(self) -> str:
        """Detailed representation of the TCB."""
        return f"Tcb(status={self.status}, date={self.date!r}, advisory_ids={self.advisory_ids!r})"


def combine_tcb_status(*statuses: TcbStatus) -> TcbStatus:
    """
    Combine multiple TCB statuses by taking the worst (highest priority) status.

    Priority order (worst to best):
    1. NotSupported
    2. Revoked
    3. OutOfDateConfigurationNeeded
    4. OutOfDate
    5. ConfigurationAndSWHardeningNeeded
    6. ConfigurationNeeded
    7. SWHardeningNeeded
    8. UpToDate

    Args:
        *statuses: Variable number of TcbStatus values to combine

    Returns:
        TcbStatus: The worst (highest priority) status from the input statuses
    """
    if not statuses:
        return TcbStatus.NOT_SUPPORTED

    # Check for each status in priority order (worst to best)
    for status in statuses:
        if status == TcbStatus.NOT_SUPPORTED:
            return TcbStatus.NOT_SUPPORTED

    for status in statuses:
        if status == TcbStatus.REVOKED:
            return TcbStatus.REVOKED

    for status in statuses:
        if status == TcbStatus.OUT_OF_DATE_CONFIGURATION_NEEDED:
            return TcbStatus.OUT_OF_DATE_CONFIGURATION_NEEDED

    for status in statuses:
        if status == TcbStatus.OUT_OF_DATE:
            return TcbStatus.OUT_OF_DATE

    for status in statuses:
        if status == TcbStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED:
            return TcbStatus.CONFIGURATION_AND_SW_HARDENING_NEEDED

    for status in statuses:
        if status == TcbStatus.CONFIGURATION_NEEDED:
            return TcbStatus.CONFIGURATION_NEEDED

    for status in statuses:
        if status == TcbStatus.SW_HARDENING_NEEDED:
            return TcbStatus.SW_HARDENING_NEEDED

    for status in statuses:
        if status == TcbStatus.UP_TO_DATE:
            return TcbStatus.UP_TO_DATE

    # Should not reach here, but return NOT_SUPPORTED as fallback
    return TcbStatus.NOT_SUPPORTED


def tcb_verify(
    tcb_info: Dict[str, Any], sgx_tcb_dict: Dict[str, int], tee_tcb_svn: bytes
) -> Dict[str, Tcb]:
    """
    Verify the TCB Info against the provided SGX and TDX TCB values.

    Implements the Intel TCB level matching algorithm from the PCS API documentation.

    Args:
        tcb_info: Parsed TCB Info structure as a dictionary
        sgx_tcb_dict: Dictionary of SGX TCB components from PCK certificate TCB extension
                      Keys: 'SGX_TCB_COMP01_SVN' through 'SGX_TCB_COMP16_SVN','PCESVN' and 'CPUSVN'
        tee_tcb_svn: 16-byte TEE TCB SVN array from quote

    Returns:
        dict: Dictionary with keys:
            - 'platform_tcb': Tcb object for the platform TCB evaluation
            - 'tdx_module_tcb': Tcb object for the TDX module evaluation (if applicable)
    """
    # Initialize default values
    platform_status = TcbStatus.NOT_SUPPORTED
    platform_date = None
    platform_advisory_ids = []

    logger.debug(f"TCB Info keys: {list(tcb_info.keys())}")

    # Extract SGX TCB components (01-16) from the dictionary
    sgx_tcb_components = [
        sgx_tcb_dict.get(f"SGX_TCB_COMP{i:02d}_SVN") for i in range(1, 17)
    ]

    # Validate that all SGX TCB components are present
    if any(comp is None for comp in sgx_tcb_components):
        missing = [i + 1 for i, comp in enumerate(sgx_tcb_components) if comp is None]
        raise ValueError(f"Platform certificate missing SGX TCB components: {missing}")

    logger.debug(f"Platform SGX TCB Components: {sgx_tcb_components}")

    # PCESVN from dictionary
    pcesvn = sgx_tcb_dict.get("PCESVN")
    if pcesvn is None:
        raise ValueError("Platform certificate missing PCESVN")

    logger.debug(f"Platform PCESVN: {pcesvn}")

    # Convert TEE TCB SVN bytes to integer array for comparison
    tee_tcb_svn_array = list(tee_tcb_svn)  # Convert 16 bytes to list of 16 integers
    logger.debug(f"Platform TEE TCB SVN Array: {tee_tcb_svn_array}")

    # Extract tcbLevels from the TCB Info structure
    tcb_levels = tcb_info.get("tcbLevels", [])
    logger.debug(f"Number of TCB levels in TCB info: {len(tcb_levels)}")

    if not tcb_levels:
        raise ValueError("TCB Info structure missing 'tcbLevels' field")

    # Step 3: Go over the sorted collection of TCB Levels
    for i, tcb_level in enumerate(tcb_levels):
        logger.debug(f" Checking TCB Level {i} ")
        tcb_data = tcb_level.get("tcb")
        if not tcb_data:
            raise ValueError(f"TCB Level {i} missing required 'tcb' field")

        logger.debug(f"TCB Level Status: {tcb_level.get('tcbStatus')}")
        logger.debug(f"TCB Level Date: {tcb_level.get('tcbDate')}")

        # Step 3.a: Compare all SGX TCB Comp SVNs (01 to 16)
        sgx_components = tcb_data.get("sgxtcbcomponents")
        if not sgx_components:
            raise ValueError(f"TCB Level {i} missing required 'sgxtcbcomponents' field")

        logger.debug(f"Comparing {len(sgx_components)} SGX TCB components")
        sgx_matches = []
        for i in range(len(sgx_components)):
            platform_val = sgx_tcb_components[i]
            tcb_val = sgx_components[i].get("svn")
            match = platform_val >= tcb_val
            sgx_matches.append(match)
            logger.debug(
                f"  SGX Component {i+1:02d}: Platform={platform_val}, TCB Level={tcb_val}, Match={match}"
            )

        sgx_match = all(sgx_matches)
        logger.debug(f"Result: SGX components match = {sgx_match}")
        if not sgx_match:
            logger.debug("  -> Moving to next TCB level (SGX components don't match)")
            continue  # Move to next TCB level

        # Step 3.b: Compare PCESVN
        tcb_pcesvn = tcb_data.get("pcesvn")
        if tcb_pcesvn is None:
            raise ValueError(f"TCB Level {i} missing required 'pcesvn' field")

        pcesvn_match = pcesvn >= tcb_pcesvn
        logger.debug(f"Comparing PCESVN")
        logger.debug(
            f"  Platform PCESVN={pcesvn}, TCB Level PCESVN={tcb_pcesvn}, Match={pcesvn_match}"
        )
        if not pcesvn_match:
            logger.debug("  -> Moving to next TCB level (PCESVN doesn't match)")
            continue  # Move to next TCB level

        # Step 3.c: Compare TEE TCB SVN array
        tdx_components = tcb_data.get("tdxtcbcomponents")
        if not tdx_components:
            raise ValueError(f"TCB Level {i} missing required 'tdxtcbcomponents' field")

        # Determine which indices to compare based on TEE TCB SVN[1]
        # If TEE TCB SVN at index 1 is 0, compare indices 0-15
        # Otherwise, compare indices 2-15
        if tee_tcb_svn_array[1] == 0:
            start_index = 0
            logger.debug(f"TEE TCB SVN[1] = 0, comparing indices 0-15")
        else:
            start_index = 2
            logger.debug(f"TEE TCB SVN[1] != 0, comparing indices 2-15")

        logger.debug(f"Comparing TDX TCB components (starting at index {start_index})")

        tdx_matches = []
        for i in range(start_index, len(tdx_components)):
            platform_val = tee_tcb_svn_array[i]
            tcb_val = tdx_components[i].get("svn")
            match = platform_val >= tcb_val
            tdx_matches.append(match)
            logger.debug(
                f"  TDX Component {i:02d}: Platform={platform_val}, TCB Level={tcb_val}, Match={match}"
            )

        tdx_match = all(tdx_matches)
        logger.debug(f"TDX components match = {tdx_match}")
        if not tdx_match:
            logger.debug("  -> Moving to next TCB level (TDX components don't match)")
            continue  # Move to next TCB level

        # If we reach here, we found a matching TCB level
        logger.debug(f" Match found TCB Level {i}")
        platform_status = TcbStatus.from_string(
            tcb_level.get("tcbStatus", "NotSupported")
        )
        platform_date = tcb_level.get("tcbDate")
        platform_advisory_ids = tcb_level.get("advisoryIDs", [])
        logger.debug(f"Matched TCB Status: {platform_status.value}")
        logger.debug(f"Matched TCB Date: {platform_date}")
        logger.debug(f"Matched Advisory IDs: {platform_advisory_ids}")
        break  # Found matching level

    platform_tcb = Tcb(
        status=platform_status, date=platform_date, advisory_ids=platform_advisory_ids
    )

    # Step 4: If no match found, TCB level is not supported (already set as default)
    if platform_status == TcbStatus.NOT_SUPPORTED:
        logger.debug("No match found - TCB Level NOT SUPPORTED")
        # Create the result dictionary with only platform TCB
        return {"platform_tcb": platform_tcb, "tdx_module_tcb": None}

    # Step 5: Additional TCB status evaluation for TDX module
    # Only if TEE TCB SVN at index 1 >= 1
    module_tcb = None
    if tee_tcb_svn_array[1] >= 1:
        logger.debug(f" TDX Module Evaluation ")
        logger.debug(f"TEE TCB SVN[1] = {tee_tcb_svn_array[1]} (>= 1, checking module)")

        tdx_module_identities = tcb_info.get("tdxModuleIdentities", [])
        logger.debug(f"Number of TDX Module Identities: {len(tdx_module_identities)}")

        # Find matching TDX Module Identity with id "TDX_<version>"
        tdx_version = tee_tcb_svn_array[1]
        tdx_module_id = f"TDX_{tdx_version:02d}"
        logger.debug(f"Looking for TDX Module ID: {tdx_module_id}")

        matching_module = None
        for module in tdx_module_identities:
            module_id = module.get("id")
            logger.debug(f"  Checking module ID: {module_id}")
            if module_id == tdx_module_id:
                matching_module = module
                logger.debug(f"  -> Match found!")
                break

        if matching_module:
            # Go over TCB Levels for this module
            module_tcb_levels = matching_module.get("tcbLevels")
            platform_isvsvn = tee_tcb_svn_array[0]
            logger.debug(
                f"Number of module TCB levels to check: {len(module_tcb_levels)}"
            )
            module_status_found = False

            for mod_i, module_tcb_level in enumerate(module_tcb_levels):
                logger.debug(f" Checking Module TCB Level {mod_i} ")
                module_tcb_data = module_tcb_level.get("tcb")
                module_isvsvn = module_tcb_data.get("isvsvn")
                # Compare TEE TCB SVN at index 0 with isvsvn

                isvsvn_match = platform_isvsvn >= module_isvsvn
                logger.debug(
                    f"  Comparing ISVSVN: Platform TEE TCB SVN[0]={platform_isvsvn}, Module ISVSVN={module_isvsvn}, Match={isvsvn_match}"
                )

                if isvsvn_match:
                    # Found matching module TCB level
                    logger.debug(f"  *** MODULE MATCH FOUND at Level {mod_i} ***")
                    module_status = TcbStatus.from_string(
                        module_tcb_level.get("tcbStatus", "NotSupported")
                    )
                    module_date = module_tcb_level.get("tcbDate")
                    module_advisory_ids = module_tcb_level.get("advisoryIDs", [])

                    logger.debug(f"  Module Status: {module_status.value}")
                    logger.debug(f"  Module Date: {module_date}")
                    logger.debug(f"  Module Advisory IDs: {module_advisory_ids}")

                    # Create module TCB object
                    module_tcb = Tcb(
                        status=module_status,
                        date=module_date,
                        advisory_ids=module_advisory_ids,
                    )

                    module_status_found = True
                    break
                else:
                    logger.debug(f"  -> No match, checking next module level")

            # Step 6: If no module TCB level matches, set to NOT_SUPPORTED
            if not module_status_found:
                logger.debug(f"  No module match found - Setting to NOT_SUPPORTED")
                module_tcb = Tcb(status=TcbStatus.NOT_SUPPORTED)
        else:
            logger.debug(f"No matching TDX Module Identity found for {tdx_module_id}")
            module_tcb = Tcb(status=TcbStatus.NOT_SUPPORTED)
    else:
        logger.debug(f" Skipping TDX Module Evaluation ")

    logger.debug(f" TCB INFO VERIFICATION RESULT ")
    logger.debug(f"Platform TCB: {platform_tcb}")
    if module_tcb:
        logger.debug(f"Module TCB: {module_tcb}")

    return {"platform_tcb": platform_tcb, "tdx_module_tcb": module_tcb}
