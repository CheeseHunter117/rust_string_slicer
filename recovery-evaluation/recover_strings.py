import argparse
import json
import pathlib
import sys

from binaryninja import core_version, load

# Add parent directory to system path to be able to import and use rsut_string_slicer scripts
sys.path.append(str(pathlib.Path(__file__).parent.parent))
from binja_plugin.actions import RecoverStringFromReadOnlyDataTask, RustStringSlice


def main():
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

    args = parser.parse_args()

    recovered_string_slices = []
    with load(args.binary) as bv:
        if not RustStringSlice.check_binary_ninja_type_exists(bv):
            RustStringSlice.create_binary_ninja_type(bv)

        task = RecoverStringFromReadOnlyDataTask(bv)
        recovered_string_slices = task.run()

    # Call to decode should never fail because it is checked inside RecoverStringFromReadOnlyDataTask already.
    strings = [r.data.decode("utf-8") for r in recovered_string_slices]

    # Dedup and sort
    strings = list(set(strings))
    strings.sort()

    json_str = json.dumps(
        {
            "binary ninja version": core_version(),
            "binary": str(args.binary),
            "strings": strings,
        }
    )

    if args.output is not None:
        with open(args.output, "w") as f:
            f.write(json_str)
    else:
        print(json_str)


if __name__ == "__main__":
    main()
