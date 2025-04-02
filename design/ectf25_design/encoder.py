#!/usr/bin/env python3
"""
Author: Jacob Wyrozebski

eCTF 2025 Secure Encoder - Uses AES-256-GCM + HMAC-SHA256
"""

import argparse
import struct
import json
import os
import secrets
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAX_FRAME_SIZE = 64
MAX_CHANNEL = 0xFFFF  # 16-bit channel number
SECRETS_FILE = "/etc/ectf25/secrets.json"

class Encoder:
    def __init__(self, secrets_path: str = SECRETS_FILE):
        """ Loads AES-256 and HMAC-SHA256 keys securely from the secrets file. """
        if not os.path.exists(secrets_path):
            raise FileNotFoundError(f"Secrets file not found: {secrets_path}")

        with open(secrets_path, "r") as f:
            secrets_dict = json.load(f)

        try:
            self.aes_key = bytes.fromhex(secrets_dict["aes_key"])
            self.hmac_key = bytes.fromhex(secrets_dict["hmac_key"])
            self.allowed_channels = set(secrets_dict["channels"])
        except KeyError as e:
            raise ValueError(f"Missing key in secrets file: {e}")

    def is_channel_allowed(self, channel: int) -> bool:
        """ Validate if the given channel is allowed. """
        return channel in self.allowed_channels

    def _hmac_sha256(self, header: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """ Generates HMAC-SHA256 authentication tag. """
        return hmac.new(self.hmac_key, header + nonce + ciphertext, hashlib.sha256).digest()

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        """ Encrypts and signs a frame using AES-256-GCM and HMAC-SHA256. """
        if channel not in self.allowed_channels:
            raise ValueError(f"Unauthorized channel: {channel}")
        if len(frame) > MAX_FRAME_SIZE:
            raise ValueError(f"Frame exceeds max size ({MAX_FRAME_SIZE} bytes).")

        header = struct.pack("<IQ", channel, timestamp)
        nonce = secrets.token_bytes(12)  # Secure nonce generation
        aesgcm = AESGCM(self.aes_key)
        ciphertext = aesgcm.encrypt(nonce, frame, header)  # Encrypt frame with AES-GCM
        hmac_signature = self._hmac_sha256(header, nonce, ciphertext)  # Generate HMAC

        return header + nonce + ciphertext + hmac_signature

def main():
    """ Main function for encoding a frame securely. """
    parser = argparse.ArgumentParser(prog="encoder")
    parser.add_argument("secrets_file", type=str, help="Path to secrets.json file")
    parser.add_argument("channel", type=int, help="Channel number")
    parser.add_argument("frame", help="Frame contents")
    parser.add_argument("timestamp", type=int, help="64-bit timestamp")
    args = parser.parse_args()

    try:
        encoder = Encoder(args.secrets_file)
        encoded_frame = encoder.encode(args.channel, args.frame.encode(), args.timestamp)
        print(encoded_frame.hex())  # Output encoded frame in hex format
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
