"""
This is a quick demo/test script which shows how to use the python wrapper
around the Pickled Canary search tool.

It's currently not packaged up nicely!

The "dll_path" below assumes you've built the rust code like this:

    cargo build --target=i686-pc-windows-msvc

which also assumes you're using a 32-bit python version. The exact build used
and the path to use below may have to change based on your target platform.

More to come...

"""
# Copyright (C) 2023 The MITRE Corporation All Rights Reserved

import pprint
import sys
import os

# dll_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "target", "i686-pc-windows-msvc", "debug")
# os.add_dll_directory(dll_path)

from pickled_canary import (
    PatternOffsetResults,
    LazyPatternOffsetResults,
    PatternFullResults,
)

pattern_str = """{"tables":[],"steps":[{"type":"LABEL", "value":"foo"},{"type":"BYTE","value":116},{"type":"BYTE","value":102},{"type":"BYTE","value":116},{"type":"BYTE","value":112},{"type":"BYTE","value":95},{"type":"BYTE","value":114},{"type":"BYTE","value":120},{"type":"MATCH"}]}"""
test_data = b"aaatftp_rxddtftp_rxasdfasdf"


def test_basics():
    results = []
    for result in PatternOffsetResults.create_and_run(pattern_str, test_data):
        results.append(result)
    assert results == [3, 12]


def test_full():
    results = []
    for result in PatternFullResults.create_and_run(pattern_str, test_data):
        results.append(result)

    assert len(results)
    assert results[0].status == 1
    assert results[0].start == 3
    assert results[0].labels[b"foo"] == 3
    assert results[1].status == 1
    assert results[1].start == 12
    assert results[1].labels[b"foo"] == 12


def test_lazy():
    lazy = LazyPatternOffsetResults.create_pattern(pattern_str, test_data)
    results = []
    for result in lazy:
        results.append(result)
    assert results == [3, 12]


if __name__ == "__main__":
    test_basics()
    test_lazy()
