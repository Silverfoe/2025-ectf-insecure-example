"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import json
import secrets
import binascii
from pathlib import Path
from loguru import logger


def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents of the secrets file with strong cryptographic keys.

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder.

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list.

    :returns: JSON-encoded secrets file content.
    """

    # Generate cryptographic keys
    aes_key = secrets.token_bytes(32)  # AES-256 key (32 bytes)
    hmac_key = secrets.token_bytes(32)  # HMAC-SHA256 key (32 bytes)

    # Encode keys as hex strings for storage in JSON
    secrets_data = {
        "channels": channels,  # List of valid channels
        "aes_key": binascii.hexlify(aes_key).decode(),  # Convert to hex string
        "hmac_key": binascii.hexlify(hmac_key).decode(),  # Convert to hex string
    }

    return json.dumps(secrets_data, indent=4).encode()


def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets.

    You will likely not have to change this function.
    """
    # Parse the command line arguments
    args = parse_args()

    try:
        secrets = gen_secrets(args.channels)

        # Debugging info - Feel free to remove in production
        logger.debug(f"Generated secrets: {secrets.decode()}")

        # Open the file, erroring if the file exists unless the --force arg is provided
        with open(args.secrets_file, "wb" if args.force else "xb") as f:
            f.write(secrets)

        # Debugging output - Feel free to remove
        logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")

    except Exception as e:
        logger.error(f"Error generating secrets: {str(e)}")


if __name__ == "__main__":
    main()
