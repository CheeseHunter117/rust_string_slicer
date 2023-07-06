from dataclasses import dataclass
from pprint import pformat
from typing import List, Optional

from binaryninja.binaryview import BinaryView, DataVariable
from binaryninja.log import Logger
from binaryninja.types import IntegerType, PointerType, StructureBuilder, Type

logger = Logger(session_id=0, logger_name=__name__)


@dataclass
class RustStringSlice:
    address: int
    length: int
    data: bytes

    def __repr__(self):
        return f"StringSlice(address={self.address:#x}, length={self.length:#x}, data={self.data})"

    @classmethod
    def create_binary_ninja_type(cls, bv: BinaryView):
        if bv.arch is not None:
            rust_string_slice_bn_type_obj = StructureBuilder.create(packed=True)
            rust_string_slice_bn_type_obj.append(
                type=PointerType.create(arch=bv.arch, type=Type.char()), name="address"
            )
            rust_string_slice_bn_type_obj.append(
                type=IntegerType.create(width=bv.arch.address_size), name="length"
            )

            bv.define_user_type(
                name="RustStringSlice",
                type_obj=rust_string_slice_bn_type_obj,
            )
            logger.log_info(f"Defined new RustStringSlice type")

    @classmethod
    def create_binary_ninja_instance(cls, bv: BinaryView, location: int, name: str):
        bv.define_user_data_var(addr=location, var_type="RustStringSlice", name=name)
        logger.log_info(f"Defined new RustStringSlice at {location:#x}")


def recover_string_slices_from_readonly_data(
    bv: BinaryView,
) -> Optional[List[RustStringSlice]]:
    if bv.arch is None:
        logger.log_error("Could not get architecture of current binary view, exiting")
        return None

    readonly_segments = list(
        filter(
            lambda segment: segment.readable
            and not segment.writable
            and not segment.executable,
            bv.segments,
        )
    )
    if len(readonly_segments) == 0:
        logger.log_error("Could not find any read-only segment in binary, exiting")
        return None

    # Obtain all data vars which are pointers to data in readonly data segments
    data_vars_to_ro_segment_data: List[DataVariable] = []
    for _data_var_addr, candidate_string_slice_data_ptr in bv.data_vars.items():
        if isinstance(candidate_string_slice_data_ptr.type, PointerType):
            for readonly_segment in readonly_segments:
                if candidate_string_slice_data_ptr.value in readonly_segment:
                    data_vars_to_ro_segment_data.append(candidate_string_slice_data_ptr)
                    logger.log_debug(
                        f"Found pointer var at {candidate_string_slice_data_ptr.address:#x} ({candidate_string_slice_data_ptr}) pointing to {candidate_string_slice_data_ptr.value:#x} "
                    )

    recovered_string_slices: List[RustStringSlice] = []
    for candidate_string_slice_data_ptr in data_vars_to_ro_segment_data:
        # Try to read an integer following the data var,
        # and treat it as a candidate for a string slice length.
        candidate_string_slice_len_addr = (
            candidate_string_slice_data_ptr.address
            + candidate_string_slice_data_ptr.type.width
        )

        # Filter out anything at the candidate address
        # that's already defined as any data var type which is not an integer.
        existing_data_var_at_candidate_string_slice_len_addr = bv.get_data_var_at(
            candidate_string_slice_len_addr
        )
        if existing_data_var_at_candidate_string_slice_len_addr is not None:
            if not isinstance(
                existing_data_var_at_candidate_string_slice_len_addr.type, IntegerType
            ):
                continue

        candidate_string_slice_len = bv.read_int(
            address=candidate_string_slice_len_addr,
            size=bv.arch.address_size,  # TODO: is there a better way to get the maximum int size per platform?
            sign=False,
            endian=bv.arch.endianness,
        )

        logger.log_debug(
            f"Pointer var at {candidate_string_slice_data_ptr.address:#x} is followed by integer with value {candidate_string_slice_len:#x}"
        )

        # Filter out any potential string slice which has length 0
        if candidate_string_slice_len == 0:
            continue
        # Filter out any potential string slice which is too long
        if candidate_string_slice_len >= 0x1000:  # TODO: maybe change this limit
            continue

        # Attempt to read out the pointed to value as a string slice, with the length obtained above.
        try:
            candidate_string_slice = bv.read(
                addr=candidate_string_slice_data_ptr.value,
                length=candidate_string_slice_len,
            )
        except Exception as err:
            logger.log_error(
                f"Failed to read from address {candidate_string_slice_data_ptr.value} with length {candidate_string_slice_len}: {err}"
            )
            continue

        logger.log_debug(
            f"Obtained candidate string slice with addr {candidate_string_slice_data_ptr.value:#x}, len {candidate_string_slice_len:#x}: {candidate_string_slice}"
        )

        # Sanity check whether the recovered string is valid UTF-8
        try:
            candidate_utf8_string = candidate_string_slice.decode("utf-8")
            logger.log_info(
                f'Recovered string at addr {candidate_string_slice_data_ptr.value:#x}, len {candidate_string_slice_len:#x}: "{candidate_utf8_string}"'
            )

            # Append the final string slice object to the list of recovered strings.
            recovered_string_slices.append(
                RustStringSlice(
                    address=candidate_string_slice_data_ptr.value,
                    length=candidate_string_slice_len,
                    data=candidate_string_slice,
                )
            )

            # Set the char[<candidate_string_slice_len>] type on the location pointed to by the data var.
            existing_string_slice_data = bv.get_data_var_at(
                candidate_string_slice_data_ptr.value
            )
            if existing_string_slice_data is not None:
                bv.undefine_user_data_var(addr=candidate_string_slice_data_ptr.value)

            bv.define_user_data_var(
                addr=candidate_string_slice_data_ptr.value,
                var_type=Type.array(type=Type.char(), count=candidate_string_slice_len),
            )

            # Set the RustStringSlice type on the location of the data var.
            RustStringSlice.create_binary_ninja_instance(
                bv=bv,
                location=candidate_string_slice_data_ptr.address,
                name=f'str_"{candidate_utf8_string}"',
            )

        except UnicodeDecodeError as err:
            logger.log_warn(
                f"Candidate string slice {candidate_string_slice} does not decode to a valid UTF-8 string; excluding from final results: {err}"
            )
            continue

    return recovered_string_slices


def action_recover_string_slices_from_readonly_data(bv: BinaryView):
    RustStringSlice.create_binary_ninja_type(bv)
    bv.begin_undo_actions()
    logger.log_info(pformat(recover_string_slices_from_readonly_data(bv)))
    bv.commit_undo_actions()
    bv.update_analysis()
