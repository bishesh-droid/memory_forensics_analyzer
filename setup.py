from setuptools import setup, find_packages

setup(
    name="memory-forensics-analyzer",
    version="1.0.0",
    description="Production-grade memory forensics analysis platform",
    author="Bishesh Baruah",
    author_email="bisheshbaruah56@gmail.com",
    packages=find_packages(),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "mfa = memory_forensics_analyzer.main:main",
            "mem-analyze = memory_forensics_analyzer.main:main",
        ],
    },
    install_requires=[
        "volatility3",
        "pefile",
    ],
    extras_require={
        "full": [
            "yara-python",
            "fastapi",
            "uvicorn[standard]",
        ],
        "dev": [
            "pytest",
            "pytest-cov",
            "mypy",
            "ruff",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: Other/Proprietary License",
    ],
)
