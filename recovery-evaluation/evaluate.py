import argparse
import json
import logging
import pathlib
import string
import subprocess
from enum import Enum
from sys import exit, stderr
from typing import Optional

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


def determine_string_finder() -> Optional[StringFinder]:
    try:
        proc = subprocess.run(["rg", "--version"], capture_output=True)
        if proc.returncode == 0:
            return StringFinder.Ripgrep
    except FileNotFoundError:
        pass

    try:
        proc = subprocess.run(["grep", "--version"], capture_output=True)
        if proc.returncode == 0:
            return StringFinder.Grep
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
                if check_for_presence(s, binary, string_finder):
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
    arguments = ["-q", extracted_str, str(binary)]
    match string_finder:
        case StringFinder.Ripgrep:
            arguments.insert(0, "rg")
        case StringFinder.Grep:
            arguments.insert(0, "grep")

    try:
        proc = subprocess.run(arguments, capture_output=True)
        return proc.returncode == 0
    except ValueError as ve:
        logger.warning(f"Could not check for presence of {repr(extracted_str)}: {ve}")


def main():
    parser = argparse.ArgumentParser()
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
        "-l",
        "--loglevel",
        metavar="LOG-LEVEL",
        help="Log level to display to stderr. Possible values are %(choices)s. (default: %(default)s)",
        default="warning",
        choices=["debug", "info", "warning", "error", "critical"],
        type=str,
    )

    args = parser.parse_args()
    logger.setLevel(LOG_LEVELS[args.loglevel])
    logger.debug(f"main: {args=}")

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
        f"{len(recovered_json['strings'])} strings were recovered from the binary."
    )

    string_finder = determine_string_finder()
    logger.debug(f"{string_finder=}")
    if string_finder is None:
        logger.error("Either ripgrep (rg) or grep need to be installed on the system")
        exit(1)

    extracted_strings_present = filter_extracted(
        extracted_json, args.binary, string_finder
    )
    extracted_set = set(extracted_strings_present)
    recovered_set = set(recovered_json["strings"])

    logger.info(
        f"{len(extracted_strings_present)} of the extracted literal strings were found in the actual binary."
    )
    logger.info(f"{len(extracted_set)} with duplicates being removed.")

    present_in_both = extracted_set.intersection(recovered_set)
    logger.debug(f"{present_in_both=}")
    logger.info(
        f"{len(present_in_both)} appear in the duplicate free ones and the recovered ones."
    )

    quota = len(present_in_both) / len(extracted_set)
    print(f"{len(present_in_both)} / {len(extracted_set)} = {quota:.2%}")

    missing_from_recovered = extracted_set.difference(recovered_set)
    logger.info(f"{len(missing_from_recovered)} are missing from recovered.")

    with open("/tmp/Json.json", "w") as f:
        json.dump(list(missing_from_recovered), f)


if __name__ == "__main__":
    main()
