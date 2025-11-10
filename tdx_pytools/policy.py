# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Policy validation framework for Intel TDX attestation reports.

import json
import os
from typing import Any, Dict, List, Optional, Union

from .quote import Quote
from .tcb import Tcb, TcbStatus
from .tdx_logging import get_logger

logger = get_logger(__name__)


class PolicyValidationError(Exception):
    """Exception raised when policy validation fails."""

    pass


class AttestationPolicy:
    """
    AttestationPolicy - Validates TDX attestation quotes against security policies

    This class loads and validates attestation quotes against predefined security policies
    specified in JSON format.
    """

    def __init__(
        self,
        policy_data: Optional[Dict[str, Any]] = None,
        policy_file: Optional[str] = None,
    ):
        """
        Initialize AttestationPolicy from JSON data or file.

        Args:
            policy_data: Dictionary containing policy rules
            policy_file: Path to JSON file containing policy rules

        Raises:
            ValueError: If neither policy_data nor policy_file is provided, or if the policy file is invalid
            FileNotFoundError: If policy_file doesn't exist
            json.JSONDecodeError: If policy file contains invalid JSON
        """
        if policy_data is not None:
            self.policy = policy_data
        elif policy_file is not None:
            self.policy = self._load_policy_file(policy_file)
        else:
            raise ValueError("Either policy_data or policy_file must be provided")

        self._validate_policy_structure()

    def _load_policy_file(self, policy_file: str) -> Dict[str, Any]:
        """Load policy from JSON file."""
        if not os.path.exists(policy_file):
            raise FileNotFoundError(f"Policy file not found: {policy_file}")

        with open(policy_file, "r") as f:
            return json.load(f)

    def _validate_policy_structure(self) -> None:
        """Validate that the policy has the expected structure."""
        required_sections = ["metadata", "validation_rules"]
        for section in required_sections:
            if section not in self.policy:
                raise ValueError(f"Policy missing required section: {section}")

    def validate_quote(
        self,
        quote: Quote,
        tcb_dict: Dict[str, Tcb],
        report_data: bytes = None,
    ) -> bool:
        """
        Validate an attestation quote against the policy.

        Args:
            quote: Quote object to validate
            tcb_dict: TCB dictionary for TCB level validations
            report_data: Optional report_data to validate against the quote's report_data field

        Returns:
            True if quote passes all policy checks

        Raises:
            PolicyValidationError: If any policy check fails
        """
        logger.info(
            f"Validating quote against policy: {self.policy.get('metadata', {}).get('name', 'Unknown')}"
        )
        logger.debug(self.get_policy_summary())

        # Validate report_data if provided
        if report_data is not None:
            logger.info("Validating provided report_data against quote")

            # Convert report_data to bytes if it's a string (hex format)
            if isinstance(report_data, str):
                try:
                    # Remove any hex prefix and convert to bytes
                    hex_string = self._normalize_hex_string(report_data)
                    report_data_bytes = bytes.fromhex(hex_string)
                except ValueError as e:
                    error_msg = f"Invalid hex string format for report_data: {e}"
                    logger.error(error_msg)
                    raise PolicyValidationError(error_msg)
            else:
                report_data_bytes = report_data

            if quote.body.report_data != report_data_bytes:
                error_msg = f"Report data mismatch: expected {report_data_bytes.hex()}, got {quote.body.report_data.hex()}"
                logger.error(error_msg)
                raise PolicyValidationError(error_msg)
            else:
                logger.info("Report data validation passed")

        validation_results = []
        rules = self.policy.get("validation_rules", {})

        # Handle TCB validation separately
        if "tcb" in rules:
            tcb_rules = rules.pop("tcb")
            logger.info("Validating TCB levels")

            try:
                # Validate update status
                expected_update = tcb_rules.pop("update", "standard")
                if expected_update == "early":
                    if tcb_dict.get("update") != "early":
                        error_msg = f"TCB update status validation failed: expected 'early', got '{tcb_dict.get('update')}'"
                        logger.error(error_msg)
                        raise PolicyValidationError(error_msg)
                logger.info(
                    f"TCB update status validation passed: required at least {expected_update}, got {tcb_dict.get('update')}"
                )

                # Validate each TCB component
                error_msgs = []
                for tcb_name, expected_status_str in tcb_rules.items():
                    if tcb_name not in tcb_dict:
                        error_msg = (
                            f"TCB component '{tcb_name}' not found in TCB dictionary"
                        )
                        logger.error(error_msg)
                        raise PolicyValidationError(error_msg)

                    tcb = tcb_dict[tcb_name]
                    if not isinstance(tcb, Tcb):
                        error_msg = f"Invalid TCB object for '{tcb_name}'"
                        logger.error(error_msg)
                        raise PolicyValidationError(error_msg)

                    try:
                        expected_status = TcbStatus.from_string(expected_status_str)
                    except Exception as e:
                        error_msg = f"Invalid expected TCB status '{expected_status_str}' for component '{tcb_name}': {e}"
                        logger.error(error_msg)
                        raise PolicyValidationError(error_msg)

                    if not tcb.status.compare_status(expected_status):
                        error_msgs.append(
                            f"TCB component '{tcb_name}' validation failed: expected {expected_status.value}, got {tcb.status.value}"
                        )
                    logger.info(
                        f"TCB component '{tcb_name}' validation passed: {tcb.status.value}"
                    )
                if error_msgs:
                    for msg in error_msgs:
                        logger.error(msg)
                    raise PolicyValidationError(" ; ".join(error_msgs))
                logger.info("TCB validation passed")

            except Exception as e:
                logger.error(f"Error during TCB validation: {e}")
                raise PolicyValidationError(f"TCB validation error: {e}")

        # Validate each field in the policy rules
        for field_name, field_rules in rules.items():
            logger.info(f"Validating field: {field_name}")

            try:
                # Get the field value from the quote
                if not hasattr(quote, field_name):
                    logger.error(f"Field '{field_name}' not found in attestation quote")
                    validation_results.append((field_name, False))
                else:
                    field_value = getattr(quote, field_name)
                    result = self._validate_object(field_value, field_rules, field_name)
                    validation_results.append((field_name, result))

            except Exception as e:
                logger.error(f"Error validating field '{field_name}': {e}")
                validation_results.append((field_name, False))

        # Check if all validations passed
        failed_validations = [name for name, result in validation_results if not result]
        if failed_validations:
            raise PolicyValidationError(
                f"Policy validation failed for: {', '.join(failed_validations)}"
            )

        logger.info("All policy validations passed successfully!")

        return True

    def _validate_object(
        self, obj: Any, rules: Dict[str, Any], obj_name: str = ""
    ) -> bool:
        """
        Validate an object (simple field or nested object) against validation rules.

        Args:
            obj: The object to validate
            rules: Validation rules for this object
            obj_name: Name of the object for verbose output

        Returns:
            True if object passes validation
        """
        validation_passed = True

        # Handle different types of validation rules
        for rule_type, rule_value in rules.items():
            if rule_type == "exact_match":
                if not self._validate_exact_match(obj, rule_value, obj_name):
                    validation_passed = False
            elif rule_type == "min_value":
                if not self._validate_min_value(obj, rule_value, obj_name):
                    validation_passed = False
            elif rule_type == "max_value":
                if not self._validate_max_value(obj, rule_value, obj_name):
                    validation_passed = False
            elif rule_type == "allow_list":
                if not self._validate_allow_list(obj, rule_value, obj_name):
                    validation_passed = False
            elif rule_type == "deny_list":
                if not self._validate_deny_list(obj, rule_value, obj_name):
                    validation_passed = False
            elif rule_type == "boolean":
                if not self._validate_boolean(obj, rule_value, obj_name):
                    validation_passed = False
            else:
                # Handle nested attribute validation - get the attribute and validate it recursively
                if not hasattr(obj, rule_type):
                    logger.error(f"Field '{rule_type}' not found in {obj_name}")
                    validation_passed = False
                else:
                    attr_value = getattr(obj, rule_type)
                    attr_name = f"{obj_name}.{rule_type}" if obj_name else rule_type

                    # Handle all validation rules recursively
                    if isinstance(rule_value, dict):
                        # Complex validation rules - recurse
                        if not self._validate_object(attr_value, rule_value, attr_name):
                            validation_passed = False
                    else:
                        # Simple values - wrap them in a rules dict and recurse
                        if isinstance(rule_value, bool):
                            wrapped_rules = {"boolean": rule_value}
                        else:
                            wrapped_rules = {"exact_match": rule_value}
                        if not self._validate_object(
                            attr_value, wrapped_rules, attr_name
                        ):
                            validation_passed = False

        return validation_passed

    def _validate_exact_match(
        self, field_value: Any, expected_value: Any, field_name: str = ""
    ) -> bool:
        """Validate that field value exactly matches expected value."""
        if isinstance(field_value, bytes):
            # Handle byte fields by converting expected hex string to bytes
            if isinstance(expected_value, str):
                expected_bytes = bytes.fromhex(
                    self._normalize_hex_string(expected_value)
                )
                if field_value != expected_bytes:
                    logger.error(f"{field_name} value mismatch:")
                    logger.error(f"   Expected: {expected_value}")
                    logger.error(f"   Actual:   {field_value.hex()}")
                    return False
            else:
                if field_value != expected_value:
                    logger.error(
                        f"{field_name} value mismatch: {field_value} != {expected_value}"
                    )
                    return False
        else:
            if field_value != expected_value:
                logger.error(
                    f"{field_name} value mismatch: {field_value} != {expected_value}"
                )
                return False

        logger.debug(f"{field_name} exact match validation passed: {field_value}")
        return True

    def _validate_min_value(
        self, field_value: Any, min_value: Any, field_name: str = ""
    ) -> bool:
        """Validate that field value is >= minimum value."""
        if field_value < min_value:
            logger.error(
                f"{field_name} value {field_value} < required minimum {min_value}"
            )
            return False
        logger.debug(
            f"{field_name} minimum value validation passed: {field_value} >= {min_value}"
        )
        return True

    def _validate_max_value(
        self, field_value: Any, max_value: Any, field_name: str = ""
    ) -> bool:
        """Validate that field value is <= maximum value."""
        if field_value > max_value:
            logger.error(
                f"{field_name} value {field_value} > allowed maximum {max_value}"
            )
            return False
        logger.debug(
            f"{field_name} maximum value validation passed: {field_value} <= {max_value}"
        )
        return True

    def _validate_allow_list(
        self,
        field_value: Any,
        allowed_values: List[Any],
        field_name: str = "",
    ) -> bool:
        """Validate that field value is in list of allowed values."""
        if field_value not in allowed_values:
            logger.error(
                f"{field_name} value {field_value} not in allow list {allowed_values}"
            )
            return False
        logger.debug(
            f"{field_name} allow list validation passed: {field_value} in {allowed_values}"
        )
        return True

    def _validate_deny_list(
        self,
        field_value: Any,
        denied_values: List[Any],
        field_name: str = "",
    ) -> bool:
        """Validate that field value is not in list of denied values."""
        if field_value in denied_values:
            logger.error(
                f"{field_name} value {field_value} found in deny list {denied_values}"
            )
            return False
        logger.debug(
            f"{field_name} deny list validation passed: {field_value} not in {denied_values}"
        )
        return True

    def _validate_boolean(
        self,
        field_value: Any,
        expected_value: bool,
        field_name: str = "",
    ) -> bool:
        """Validate that field value matches expected boolean value."""
        if field_value != expected_value:
            logger.error(f"{field_name} is {field_value}, expected {expected_value}")
            return False
        logger.debug(f"{field_name} is correctly set to {expected_value}")
        return True

    def _normalize_hex_string(self, hex_str: str) -> str:
        """Normalize hex string by removing prefixes and converting to lowercase."""
        if hex_str.startswith("0x"):
            hex_str = hex_str[2:]
        return hex_str.lower()

    def get_policy_summary(self) -> str:
        """Get a human-readable summary of the policy."""
        metadata = self.policy.get("metadata", {})
        rules = self.policy.get("validation_rules", {})

        summary = []
        summary.append(f"Policy: {metadata.get('name', 'Unknown')}")
        summary.append(f"Version: {metadata.get('version', 'Unknown')}")
        summary.append(f"Description: {metadata.get('description', 'No description')}")
        summary.append("")
        summary.append("Validation Rules:")

        self._format_rules_summary(rules, summary, "  ")

        return "\n".join(summary)

    def _format_rules_summary(
        self, rules: Dict[str, Any], summary: List[str], indent: str
    ) -> None:
        """Recursively format validation rules for the summary."""
        for field_name, field_rules in rules.items():
            if isinstance(field_rules, dict):
                summary.append(f"{indent}- {field_name}:")
                for rule_type, rule_value in field_rules.items():
                    if rule_type in [
                        "exact_match",
                        "min_value",
                        "max_value",
                        "allow_list",
                        "deny_list",
                        "boolean",
                    ]:
                        summary.append(f"{indent}  • {rule_type}: {rule_value}")
                    elif isinstance(rule_value, dict):
                        summary.append(f"{indent}  • {rule_type}:")
                        self._format_rules_summary(rule_value, summary, indent + "    ")
                    else:
                        summary.append(f"{indent}  • {rule_type}: {rule_value}")
            else:
                summary.append(f"{indent}- {field_name}: {field_rules}")


def validate_quote_with_policy(
    quote: Quote,
    tcb_dict: Dict[str, Tcb],
    policy_file: str,
    report_data: bytes = None,
) -> bool:
    """
    Convenience function to validate a quote against a policy file.

    Args:
        quote: Quote object to validate
        tcb_dict: Dictionary of TCB levels
        policy_file: Path to JSON policy file
        report_data: Optional report data to validate against

    Returns:
        True if quote passes all policy checks

    Raises:
        PolicyValidationError: If any policy check fails
    """
    policy = AttestationPolicy(policy_file=policy_file)
    return policy.validate_quote(quote, tcb_dict, report_data=report_data)
