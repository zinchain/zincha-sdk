"""Small bincode writer for the Rust transaction wire format."""

from __future__ import annotations

import struct
from typing import Callable, Iterable, Optional, TypeVar, Union

BigNumberish = Union[int, str]
T = TypeVar("T")


def as_u64(value: BigNumberish, field: str = "value") -> int:
    parsed = int(value)
    if parsed < 0 or parsed > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError("%s must fit in unsigned 64 bits" % field)
    return parsed


def as_u32(value: int, field: str = "value") -> int:
    if int(value) != value or value < 0 or value > 0xFFFF_FFFF:
        raise ValueError("%s must fit in unsigned 32 bits" % field)
    return int(value)


def as_u8(value: int, field: str = "value") -> int:
    if int(value) != value or value < 0 or value > 0xFF:
        raise ValueError("%s must fit in unsigned 8 bits" % field)
    return int(value)


class BincodeWriter:
    def __init__(self) -> None:
        self._chunks = []

    def write_u8(self, value: int) -> None:
        self._chunks.append(bytes([as_u8(value)]))

    def write_u32(self, value: int) -> None:
        self._chunks.append(as_u32(value).to_bytes(4, "little"))

    def write_u64(self, value: BigNumberish) -> None:
        self._chunks.append(as_u64(value).to_bytes(8, "little"))

    def write_f32(self, value: float) -> None:
        self._chunks.append(struct.pack("<f", float(value)))

    def write_f64(self, value: float) -> None:
        self._chunks.append(struct.pack("<d", float(value)))

    def write_string(self, value: str) -> None:
        self.write_bytes(value.encode("utf-8"))

    def write_bytes(self, value: bytes) -> None:
        self.write_u64(len(value))
        self._chunks.append(bytes(value))

    def write_raw(self, value: bytes) -> None:
        self._chunks.append(bytes(value))

    def write_option(
        self,
        value: Optional[T],
        encode: Callable[["BincodeWriter", T], None],
    ) -> None:
        """bincode Option<T>: 0u8 (None) or 1u8 + T (Some)."""
        if value is None:
            self.write_u8(0)
        else:
            self.write_u8(1)
            encode(self, value)

    def write_vec(
        self,
        values: Iterable[T],
        encode: Callable[["BincodeWriter", T], None],
    ) -> None:
        """bincode Vec<T>: u64 length + each element."""
        materialized = list(values)
        self.write_u64(len(materialized))
        for value in materialized:
            encode(self, value)

    def finish(self) -> bytes:
        return b"".join(self._chunks)
