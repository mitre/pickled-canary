# Copyright (C) 2023 The MITRE Corporation All Rights Reserved

from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="Pickled-Canary",
    version="0.0.6",
    rust_extensions=[RustExtension("pickled_canary.pickled_canary_lib", binding=Binding.NoBinding, path="pclib/Cargo.toml")],
    packages=["pickled_canary"],
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
)