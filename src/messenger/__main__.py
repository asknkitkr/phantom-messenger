"""
Phantom Messenger — Entry Point.

Usage:
    python -m messenger                  # Normal mode (BLE peripheral)
    python -m messenger --mode central   # BLE central (scanner)
    python -m messenger --mode loopback  # Loopback for testing
    python -m messenger --debug          # Enable debug logging
"""

from __future__ import annotations

import argparse
import logging

from messenger.config import DATA_DIR
from messenger.crypto.keys import KeyManager
from messenger.storage.database import DatabaseManager
from messenger.transport.peripheral import (
    BLEPeripheral,
    BLECentral,
    LoopbackTransport,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="phantom",
        description="Phantom Messenger — Offline encrypted peer-to-peer messenger",
    )
    parser.add_argument(
        "--mode",
        choices=["peripheral", "central", "loopback", "none"],
        default="none",
        help=(
            "BLE mode: 'peripheral' (advertise), 'central' (scan), "
            "'loopback' (testing), 'none' (no BLE, manual key exchange only). "
            "Default: none"
        ),
    )
    parser.add_argument(
        "--data-dir",
        default=None,
        help=f"Data directory (default: {DATA_DIR})",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(DATA_DIR / "phantom.log"),
        ],
    )
    logger = logging.getLogger("messenger")
    logger.info("Starting Phantom Messenger v1.0.0")
    logger.info("Data directory: %s", DATA_DIR)

    # Initialize components
    key_manager = KeyManager()
    db_manager = DatabaseManager()

    # Select transport
    transport = None
    if args.mode == "peripheral":
        transport = BLEPeripheral()
        logger.info("Using BLE Peripheral transport.")
    elif args.mode == "central":
        transport = BLECentral()
        logger.info("Using BLE Central transport.")
    elif args.mode == "loopback":
        transport = LoopbackTransport("local")
        logger.info("Using Loopback transport (testing mode).")
    else:
        logger.info("No BLE transport selected. Manual key exchange only.")

    # Launch the TUI application
    from messenger.ui.app import PhantomApp

    app = PhantomApp(
        key_manager=key_manager,
        db_manager=db_manager,
        transport=transport,
    )

    try:
        app.run()
    except KeyboardInterrupt:
        pass
    finally:
        db_manager.close()
        logger.info("Phantom Messenger shut down.")


if __name__ == "__main__":
    main()
