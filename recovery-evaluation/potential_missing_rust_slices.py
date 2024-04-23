#!/usr/bin/env python3
import argparse
import json
import logging
import pathlib

from binaryninja import load, BinaryView
from binaryninja.types import CharType, ArrayType

# Logger Setup
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler()
streamHandler.setFormatter(
    logging.Formatter("[%(asctime)s %(levelname)s %(name)s] %(message)s")
)
logger.addHandler(streamHandler)
LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


def check_for_data_reference(string: str, bv: BinaryView) -> bool:
    logger.debug(f"Checking '{string}' (len: {len(string):#x})")

    # Early return on illogical input
    if len(string) == 0:
        return False

    # DEBUG
    if string.strip() == "" or len(string) < 5:
        return False

    for address, matched_string, linear_disassembly in bv.find_all_text(
        bv.start, bv.end, string
    ):
        undo = bv.begin_undo_actions()

        # Define address as char[] with known length.
        # Without this step, BinaryNinja will not find any data references.
        bv.define_data_var(address, ArrayType.create(CharType.create(), len(string)))

        for data_ref in bv.get_data_refs(address):
            if data_ref == address:
                logger.info(f"Found data reference to '{string}': {data_ref=}")
                return True
            elif (
                address < data_ref <= (address + len(string))
            ):  # TODO: is this an off-by-one error?
                logger.warning(
                    f"Found data reference to inside '{string}': {address=}, {data_ref=}"
                )

        bv.revert_undo_actions(undo)

    return False


def main(args: argparse.Namespace):
    with open(args.json, "r") as f:
        missing_strings = json.load(f)["missing strings"]
        logger.debug(f"{missing_strings=}")

    with load(args.binary) as bv:
        logger.debug(f"{bv=}")

        potential_rust_string_slices = [
            s for s in missing_strings if check_for_data_reference(s, bv)
        ]
        logger.info(f"{potential_rust_string_slices=}")

        if args.output is not None:
            with open(args.output, "w") as f:
                json.dump(
                    {"potential rust string slices": potential_rust_string_slices}, f
                )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        "json",
        metavar="MISSING-JSON",
        help="Path to the Missing-*.json file.\nNote: Doesn't have to have a specific file name.",
        type=pathlib.Path,
    )
    parser.add_argument(
        "binary",
        metavar="BINARY",
        help="Path to the corresponding binary.",
        type=pathlib.Path,
    )

    parser.add_argument(
        "-l",
        "--loglevel",
        metavar="LOG-LEVEL",
        help="Log level to display to stderr. Possible values are %(choices)s. (default: %(default)s)",
        default="warning",
        choices=["debug", "info", "warning", "error", "critical"],
        type=str,
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="OUTPUT",
        help="Write final output to file.",
        type=pathlib.Path,
    )

    args = parser.parse_args()
    logger.setLevel(LOG_LEVELS[args.loglevel])
    logger.debug(f"{args=}")

    main(args)
