# Copyright (C) 2025 The MITRE Corporation All Rights Reserved

from ctypes import *
from importlib.util import find_spec


class PatternResultsS(Structure):
    pass


class PatternS(Structure):
    pass


class CompareableNamedSaved(Structure):
    def __eq__(self, __o: object) -> bool:
        return self.name == getattr(__o, "name") and self.value == getattr(__o, "value")

    def __ne__(self, __o: object) -> bool:
        return self.name != getattr(__o, "name") or self.value != getattr(__o, "value")


class SavedDataValues(CompareableNamedSaved):
    _fields_ = [
        ("name", c_char_p),
        ("value", c_longlong),
    ]


u128Type = c_byte * 16


class SavedDataLabels(CompareableNamedSaved):
    _fields_ = [
        ("name", c_char_p),
        # Actually a u128... but we'll convert later
        ("value_internal", u128Type),
    ]

    @property
    def value(self):
        return int.from_bytes(self.value_internal, byteorder="little", signed=True)


class SavedDataVariables(CompareableNamedSaved):
    _fields_ = [
        ("name", c_char_p),
        ("value", c_char_p),
    ]


class SavedDataReader(Structure):
    _fields_ = [
        ("status", c_int),
        ("start", c_int64),
        ("values_len", c_int64),
        ("values_capacity", c_int64),
        ("values_internal", POINTER(SavedDataValues)),
        ("labels_len", c_int64),
        ("labels_capacity", c_int64),
        ("labels_internal", POINTER(SavedDataLabels)),
        ("variables_len", c_int64),
        ("variables_capacity", c_int64),
        ("variables_internal", POINTER(SavedDataVariables)),
    ]

    @property
    def values(self):
        out = {}
        for x in self.values_internal[: self.values_len]:
            out[x.name] = x.value
        return out

    @property
    def labels(self):
        out = {}
        for x in self.labels_internal[: self.labels_len]:
            out[x.name] = x.value
        return out

    @property
    def variables(self):
        out = {}
        for x in self.variables_internal[: self.variables_len]:
            out[x.name] = x.value
        return out

    def __repr__(self) -> str:
        return f"SavedDataReader {{ status: {self.status}, start: {self.start}, values: {self.values}, labels: {self.labels}, variables: {self.variables} }}"

    def __eq__(self, __o: object) -> bool:
        for x in ["status", "start", "values", "labels", "variables"]:
            if getattr(self, x) != getattr(__o, x):
                return False
        return True

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)


class SavedDataReaderPointer(Structure):
    _fields_ = [("data", POINTER(SavedDataReader))]

    def __del__(self):
        lib.free_saved_data_reader(self.data)


def load_lib():

    lib = cdll.LoadLibrary(find_spec(".pickled_canary_lib", "pickled_canary").origin)

    lib.load_and_run_pattern.argtypes = [
        c_char_p,
        c_char_p,
        c_uint64,
    ]
    lib.load_and_run_pattern.restype = POINTER(PatternResultsS)

    lib.iterate_results.argtypes = [POINTER(PatternResultsS)]
    lib.iterate_results.restype = c_int64

    lib.iterate_results_full.argtypes = [POINTER(PatternResultsS)]
    lib.iterate_results_full.restype = SavedDataReaderPointer

    lib.free_results.argtypes = [POINTER(PatternResultsS)]
    lib.free_results.restype = None

    lib.load_pattern.argtypes = [c_char_p]
    lib.load_pattern.restype = POINTER(PatternS)

    lib.run_pattern_once.argtypes = [
        POINTER(PatternS),
        c_char_p,
        c_uint64,
        c_uint64,
    ]
    lib.run_pattern_once.restype = c_int64

    lib.free_pattern.argtypes = [POINTER(PatternS)]
    lib.free_pattern.restype = None

    lib.free_saved_data_reader.argtypes = [POINTER(SavedDataReader)]
    lib.free_saved_data_reader.restype = None

    return lib


lib = load_lib()
