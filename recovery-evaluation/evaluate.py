#!/usr/bin/env python3

import argparse
import json
import logging
import pathlib
import string
import subprocess
from enum import Enum
from sys import exit
from typing import Optional

from potential_missing_rust_slices import find_potential_rust_string_slices
from binaryninja import load, core_version

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


class StringFinder(Enum):
    Grep = 0
    Ripgrep = 1
    RipgrepMultiline = 2


def determine_string_finder() -> Optional[StringFinder]:
    try:
        proc = subprocess.run(["grep", "--version"], capture_output=True)
        if proc.returncode == 0:
            return StringFinder.Grep
    except FileNotFoundError:
        pass

    try:
        proc = subprocess.run(["rg", "--version"], capture_output=True)
        if proc.returncode == 0:
            return StringFinder.RipgrepMultiline
    except FileNotFoundError:
        pass

    return None


def filter_extracted(
    extracted_json: dict[str, str | dict[str, list[str]]],
    binary: pathlib.Path,
    string_finder: StringFinder,
) -> dict[str, str | dict[str, list[str]]]:
    actually_present_extracted = []

    for file in extracted_json:
        for extr in file["strings"]:
            logger.debug(f"{extr=}")
            for s in split_on_format_args(extr):
                logger.debug(f"{s=}")
                if len(s) != 0 and check_for_presence(s, binary, string_finder):
                    actually_present_extracted.append(s)

    logger.debug(f"{actually_present_extracted=}")
    return actually_present_extracted


class FormatStringState(Enum):
    Start = 0
    Other = 1
    OpeningBrace = 2
    ClosingBrace = 3
    FormatArgument = 4


def split_on_format_args(literal_string: str) -> list[str]:
    if "{" in literal_string or "}" in literal_string:
        splits = []

        # NOTE: in Rust
        # - `{i:3}` legal
        # - `{i:3    }` legal
        # - `{ i:3} illegal (won't compile on stable 1.76.0)
        s = []
        state = FormatStringState.Start
        for c in literal_string:
            match state:
                case FormatStringState.Start | FormatStringState.Other:
                    if c == "{":
                        state = FormatStringState.OpeningBrace
                    elif c == "}":
                        state = FormatStringState.ClosingBrace
                    else:
                        s.append(c)
                        state = FormatStringState.Other
                case FormatStringState.OpeningBrace:
                    if c == "{":
                        s.append("{")
                        state = FormatStringState.Other
                    elif c in string.whitespace:
                        # This would not be a legal format string, but because these literal strings can have anything inside them, we will treat it as a non format argument
                        logger.warning(
                            f"A single '{{' followed by whitespace was encountered in {repr(literal_string)}"
                        )
                        s.append("{")
                        s.append(c)
                        state = FormatStringState.Other
                    else:
                        state = FormatStringState.FormatArgument
                case FormatStringState.FormatArgument:
                    # Skip all the characters in `{...}`
                    if c == "}":
                        splits.append("".join(s))
                        s = []
                        state = FormatStringState.Other
                case FormatStringState.ClosingBrace:
                    if c == "}":
                        s.append("}")
                        state = FormatStringState.Other
                    else:
                        logger.warning(
                            f"A single, unpaired '}}' was encountered in {repr(literal_string)}"
                        )
                        s.append("}")
                        state = FormatStringState.Other
        if len(s) != 0:
            splits.append("".join(s))

        return splits
    else:
        return [literal_string]


def check_for_presence(
    extracted_str: str, binary: pathlib.Path, string_finder: StringFinder
) -> bool:
    # -F / --fixed-strings makes it so that the "Pattern" input is not interpreted as a regular expression
    arguments = ["-q", "--fixed-strings", "--", extracted_str, str(binary)]
    match string_finder:
        case StringFinder.Ripgrep:
            arguments.insert(0, "rg")
        case StringFinder.RipgrepMultiline:
            # -U / --multiline gives better handling of `\n` characters
            arguments = ["rg", "--multiline"] + arguments
        case StringFinder.Grep:
            arguments.insert(0, "grep")

    try:
        proc = subprocess.run(arguments, capture_output=True)
        match proc.returncode:
            case 0:
                return True
            case 1:
                return False
            case e:  # Some other error occurred
                logger.warning(
                    f"Could not check for presence of {repr(extracted_str)}: {str(string_finder)} returned {e}"
                )
                return False
    except ValueError as ve:
        logger.warning(f"Could not check for presence of {repr(extracted_str)}: {ve}")


def main(args):
    extracted_json = {}
    with open(args.extracted, "r") as f:
        extracted_json = json.load(f)
        logger.debug(f"{extracted_json=}")
    num_extracted_strings = sum(
        [len(s) for s in [file["strings"] for file in extracted_json]]
    )
    logger.info(
        f"{num_extracted_strings} literal strings were extracted from source code."
    )

    recovered_json = {}
    with open(args.recovered, "r") as f:
        recovered_json = json.load(f)
        logger.debug(f"{recovered_json=}")
    logger.info(
        f"{len(recovered_json['strings']['rust_string_slicer'])} strings were recovered with rust_string_slicer."
    )
    logger.info(
        f"{len(recovered_json['strings']['__builtin_strncpy'])} strings were recovered from __builtin_strncy calls."
    )

    if args.string_finder is not None:
        string_finder = StringFinder[args.string_finder]
    else:
        string_finder = determine_string_finder()
        logger.debug(f"{string_finder=}")
        if string_finder is None:
            logger.error(
                "Either ripgrep (rg) or grep need to be installed on the system"
            )
            exit(1)

    extracted_strings_present = filter_extracted(
        extracted_json, args.binary, string_finder
    )
    extracted_set = set(extracted_strings_present)

    rust_slices_set = set(recovered_json["strings"]["rust_string_slicer"])
    strncpy_set = set(recovered_json["strings"]["__builtin_strncpy"])
    everything_recovered_set = rust_slices_set.union(strncpy_set)

    logger.info(
        f"{len(extracted_strings_present)} of the extracted literal strings were found in the actual binary."
    )
    logger.info(f"{len(extracted_set)} with duplicates being removed.")

    extracted_and_rust_slices = extracted_set.intersection(rust_slices_set)
    logger.debug(f"{extracted_and_rust_slices=}")
    logger.info(
        f"{len(extracted_and_rust_slices)} appear in the duplicate free ones and the rust string slices."
    )

    extracted_and_strncpy = extracted_set.intersection(strncpy_set)
    logger.debug(f"{extracted_and_strncpy=}")
    logger.info(
        f"{len(extracted_and_strncpy)} appear in the duplicate free ones and the __builtin_strncpy's."
    )

    extracted_and_everything = extracted_set.intersection(everything_recovered_set)
    logger.debug(f"{extracted_and_everything=}")
    logger.info(
        f"{len(extracted_and_everything)} appear in the duplicate free ones and all the recovered strings."
    )

    missing_from_recovered = extracted_set.difference(everything_recovered_set)
    logger.info(f"{len(missing_from_recovered)} are missing from recovered.")

    with load(args.binary) as bv:
        potential_rust_string_slices = sorted(
            find_potential_rust_string_slices(bv, list(missing_from_recovered))
        )
        logger.debug(f"{potential_rust_string_slices=}")
        logger.info(
            f"{len(potential_rust_string_slices)} of the missing strings are potential rust string slices."
        )

    if args.csv is None:
        rust_slices_quota = len(rust_slices_set) / len(extracted_set)
        potential_slices_quota = len(potential_rust_string_slices) / len(extracted_set)
        strncpy_quota = len(strncpy_set) / len(extracted_set)
        everything_quota = len(everything_recovered_set) / len(extracted_set)

        print(
            f"{len(rust_slices_set)} / {len(extracted_set)} = {rust_slices_quota:.2%}"
        )
        print(
            f"{len(potential_rust_string_slices)} / {len(extracted_set)} = {potential_slices_quota:.2%}"
        )
        print(f"{len(strncpy_set)} / {len(extracted_set)} = {strncpy_quota:.2%}")
        print(
            f"{len(everything_recovered_set)} / {len(extracted_set)} = {everything_quota:.2%}"
        )
    else:
        print(
            args.csv.join(
                [recovered_json["binary"], recovered_json["binary ninja version"]]
                + [
                    str(n)
                    for n in [
                        len(extracted_set),
                        len(extracted_strings_present),
                        len(rust_slices_set),
                        len(potential_rust_string_slices),
                        len(strncpy_set),
                        len(everything_recovered_set),
                        len(extracted_and_rust_slices),
                        len(extracted_and_strncpy),
                        len(extracted_and_everything),
                    ]
                ]
            )
        )

    if args.missing is not None:
        with open(args.missing, "w") as f:
            json.dump(
                {
                    "binary": recovered_json["binary"],
                    "binary ninja version": recovered_json["binary ninja version"],
                    "missing strings": sorted(list(missing_from_recovered)),
                },
                f,
            )

    if args.potential is not None:
        with open(args.potential, "w") as f:
            json.dump(
                {
                    "binary": recovered_json["binary"],
                    "binary ninja version": {
                        "original recovery": recovered_json["binary ninja version"],
                        "potential rust string slices recovery": core_version(),
                    },
                    "potential rust string slices": potential_rust_string_slices,
                },
                f
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        "extracted",
        metavar="EXTRACTED",
        help="Path to the JSON file with the strings extracted from the source code.",
        type=pathlib.Path,
    )
    parser.add_argument(
        "recovered",
        metavar="RECOVERED",
        help="Path to the JSON file with the strings recovered from the compiled binary.",
        type=pathlib.Path,
    )
    parser.add_argument(
        "binary",
        metavar="BINARY",
        help="Path to the binary in question. Needed for filtering strings from EXTRACTED.",
        type=pathlib.Path,
    )

    parser.add_argument(
        "-c",
        "--csv",
        metavar="DELIMITER",
        help="""Whether to render output CSV friendly.
The fields are
'binary', 'BinaryNinja version',
'num extracted', 'num extracted in binary',
'num rust slices', 'num __builtin_strncpy', 'num everything recovered',
'num intersection extracted and rust slices', 'num intersection extracted and strncpy', 'num intersection present and everything recovered'.
(default: '%(const)s')""",
        nargs="?",
        const=",",
        default=None,
        type=str,
    )
    parser.add_argument(
        "-l",
        "--loglevel",
        metavar="LOG-LEVEL",
        help="Log level to display to stderr.\nPossible values are %(choices)s.\n(default: %(default)s)",
        default="warning",
        choices=["debug", "info", "warning", "error", "critical"],
        type=str,
    )
    parser.add_argument(
        "-m",
        "--missing",
        metavar="PATH",
        help="Path to where the JSON file with the strings that are missing from the recovery should be written to.\nExisting files will be overwritten.",
        type=pathlib.Path,
    )
    parser.add_argument(
        "-p",
        "--potential",
        metavar="PATH",
        help="Path to where the JSON file with the potentially missing rust string slices should be written to.\nExisting files will be overwritten.",
        type=pathlib.Path,
    )
    parser.add_argument(
        "-s",
        "--string-finder",
        metavar="STRING-FINDER",
        help="Overwrite which string finder to use.\nPossible options are %(choices)s.",
        choices=[s.name for s in StringFinder],
        type=str,
    )

    args = parser.parse_args()
    logger.setLevel(LOG_LEVELS[args.loglevel])
    logger.debug(f"main: {args=}")

    main(args)
