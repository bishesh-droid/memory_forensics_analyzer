
from setuptools import setup, find_packages

setup(
    name="memory_forensics_analyzer",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "mem-analyze = memory_forensics_analyzer.main:main",
        ],
    },
    install_requires=[
        "volatility3",
        "pefile",
    ],
)
