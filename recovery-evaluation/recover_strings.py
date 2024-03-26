import argparse
import json
import pathlib
import sys
import logging
from typing import Optional

from binaryninja import core_version, load
from binaryninja.binaryview import BinaryView

# Add parent directory to system path to be able to import and use rsut_string_slicer scripts
sys.path.append(str(pathlib.Path(__file__).parent.parent))
from binja_plugin.actions import RecoverStringFromReadOnlyDataTask, RustStringSlice

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


def recover_rust_string_slices(bv: BinaryView) -> list[str]:
    if not RustStringSlice.check_binary_ninja_type_exists(bv):
        RustStringSlice.create_binary_ninja_type(bv)

    task = RecoverStringFromReadOnlyDataTask(bv)

    # Call to decode should never fail because it is checked inside RecoverStringFromReadOnlyDataTask already.
    return [r.data.decode("utf-8") for r in task.run()]


def recover_strncpy_strings(bv: BinaryView) -> list[str]:
    """Tries recovering strings that can be found inside BinaryNinja's GUI as `__builtin_strncpy` calls"""
    recovered_strings = []

    # strncpy(char* dst, char* src, size_t dst_size)
    # TODO: consider also looking at __builtin_strncpy
    builtin_function_symbols = [s for s in bv.symbols if str(s) == "__builtin_strncpy"]
    logger.debug(builtin_function_symbols)

    for builtin in builtin_function_symbols:
        symbols = bv.symbols[builtin]

        for s in symbols:
            logger.debug(s)
            data_var = bv.get_data_var_at(s.address)
            logger.debug(repr(data_var))

            for code_ref in data_var.code_refs:
                logger.debug(f"{repr(code_ref)} -> {repr(code_ref.mlil)}")
                params = code_ref.mlil.params
                logger.debug(params)

                # Second parameter is the string we are looking for
                # TODO: check if removing prefix and suffix is safe/smart
                recovered_strings.append(
                    str(params[1]).removeprefix('"').removesuffix('"')
                )

    return recovered_strings


def main(binary: pathlib.Path, output: Optional[pathlib.Path]):
    with load(binary) as bv:
        rust_string_slices_strings = recover_rust_string_slices(bv)
        strncpy_strings = recover_strncpy_strings(bv)

    # Dedup and sort
    rust_string_slices_strings = list(set(rust_string_slices_strings))
    rust_string_slices_strings.sort()

    strncpy_strings = list(set(strncpy_strings))
    strncpy_strings.sort()

    json_str = json.dumps(
        {
            "binary ninja version": core_version(),
            "binary": str(args.binary),
            "strings": {
                "rust_string_slicer": rust_string_slices_strings,
                "__builtin_strncpy": strncpy_strings,
            },
        }
    )

    if output is not None:
        with open(output, "w") as f:
            f.write(json_str)
    else:
        print(json_str)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "binary",
        metavar="BINARY",
        help="The Rust binary that should have its static strings recovered and exported.",
        type=pathlib.Path,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Where to write the resulting JSON file. Existing files will be overwritten.",
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

    main(args.binary, args.output)
