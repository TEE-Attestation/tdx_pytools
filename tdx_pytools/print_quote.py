# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Print quote utility - Display TDX quote contents in human-readable format.

import argparse
import sys

from . import tdx_logging
from .quote import Quote


def main() -> int:
    """
    Parse command-line arguments, read a TDX quote file, and print its details.

    Main entry point for the tdx-print command-line utility. Parses a TDX
    attestation quote file and displays its contents in human-readable format.

    Returns:
        int: Exit code (0 for success, 1 for error)

    Command-line arguments:
        -f, --file: Path to the quote file (default: quote.dat)
        -d, --debug: Enable debug mode for detailed parsing information

    Examples:
        tdx-print -f quote.dat
        tdx-print -f quote.dat --debug
    """
    parser = argparse.ArgumentParser(description="Print TDX quote details")
    parser.add_argument(
        "-f",
        "--file",
        default="quote.dat",
        help="Path to the TDX quote file (default: quote.dat)",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", default=False, help="Enable debug mode"
    )
    args = parser.parse_args()

    # Setup logging for CLI mode
    logger = tdx_logging.setup_cli_logging(verbose=args.debug, quiet=False)

    try:
        with open(args.file, "rb") as file:
            quote_data = file.read()

        logger.info(f"Reading TDX quote from: {args.file}")
        logger.info(f"File size: {len(quote_data)} bytes\n")

        quote = Quote.unpack(quote_data, debug=args.debug)
        quote.print_details()
        return 0

    except FileNotFoundError:
        logger.error(f"File '{args.file}' not found")
        return 1
    except Exception as e:
        logger.error(f"Error parsing TDX quote: {e}")
        if args.debug:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    main()
