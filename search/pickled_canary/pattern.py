# Copyright (C) 2025 The MITRE Corporation All Rights Reserved

from pickled_canary import lib
import ctypes
from abc import ABC, abstractmethod

from typing import Type, TypeVar

T = TypeVar("T", bound="PatternResults")


class PatternResults(ABC):
    """Iterable collection of offsets into a binary containing pattern matches.

    This class wraps a Rust data structure and handles freeing it when no longer
    in use.
    """

    def __init__(self, results: ctypes.POINTER(ctypes.c_void_p)):
        """Constructor. SHOULD PROBABLY NOT BE DIRECTLY CALLED!

        Use :meth:`PatternOffsetResults.create_and_run` or another classmethod
        instead

        Args:
            results (ctypes.POINTER): A pointer to a rust ResultsIterator
        """
        self.results = results

    @classmethod
    def create_and_run(cls: Type[T], pattern: str, data: bytearray) -> T:
        """Loads the given pattern, runs it against the given data, and returns
        a PatternOffsetRestults with the results.

        Args:
            pattern (str): JSON string of a compiled pattern (will be utf-8 encoded by this function)
            data (bytearray): Bytes to be searched for the given pattern

        Returns:
            PatternOffsetResults: Iterable object of results
        """
        return cls(
            lib.load_and_run_pattern(
                ctypes.c_char_p(pattern.encode("utf-8")), data, len(data)
            )
        )

    def __iter__(self):
        return self

    @abstractmethod
    def __next__(self):
        pass

    def __del__(self):
        lib.free_results(self.results)


class PatternOffsetResults(PatternResults):
    def __next__(self):
        out = lib.iterate_results(self.results)
        if out == -1:
            raise StopIteration
        return out


class PatternFullResults(PatternResults):
    def __next__(self):
        out = lib.iterate_results_full(self.results).data.contents
        if out.status <= 0:
            raise StopIteration
        return out


S = TypeVar("S", bound="LazyPatternOffsetResults")


class LazyPatternOffsetResults:
    """Iterable collection of pattern matches where each returned value is an
    offset from the previous match

    This class wraps a Rust data structure and handles freeing it when no longer
    in use.
    """

    def __init__(self, pattern: ctypes.POINTER(ctypes.c_void_p), data):
        """Constructor. SHOULD PROBABLY NOT BE DIRECTLY CALLED!

        Use :meth:`LazyPatternOffsetResults.create_pattern` or another classmethod
        instead

        Args:
            results (ctypes.POINTER): A pointer to a rust RestultsIterator
        """
        self.pattern = pattern
        self.data = data
        self.curr_offset = 0

    @classmethod
    def create_pattern(cls: Type[S], pattern: str, data: bytearray) -> T:
        """Loads the given pattern, will run it against the given data lazily, and returns
        a LazyPatternOffsetResults that can be iterated over.

        Args:
            pattern (str): JSON string of a compiled pattern (will be utf-8 encoded by this function)
            data (bytearray): Bytes to be searched for the given pattern

        Returns:
            LazyPatternOffsetResults: Iterable object of results
        """
        return cls(lib.load_pattern(ctypes.c_char_p(pattern.encode("utf-8"))), data)

    def __iter__(self):
        return self

    def __next__(self):
        offset = lib.run_pattern_once(
            self.pattern, self.data, len(self.data), self.curr_offset
        )
        if offset == -1:
            raise StopIteration

        # rebase the offset to the start index
        offset = offset + self.curr_offset

        # search from the next location
        self.curr_offset = offset + 1

        return offset

    def __del__(self):
        lib.free_pattern(self.pattern)
