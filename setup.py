"""Build configuration for the optional cross-platform native codec."""
import os

from setuptools import Extension, find_packages, setup


compile_args = ["/O2"] if os.name == "nt" else ["-O3"]

setup(
    packages=find_packages("src"),
    package_dir={"": "src"},
    ext_modules=[
        Extension(
            "thspypc.codecs._compression_native",
            ["src/thspypc/codecs/_compression_native.c"],
            py_limited_api=True,
            extra_compile_args=compile_args,
        )
    ],
    options={"bdist_wheel": {"py_limited_api": "cp310"}},
)
