from setuptools import setup, find_packages

setup(
    name="delegateguard",
    version="0.1.0",
    description="EIP-7702 delegate contract security analyzer",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "slither-analyzer>=0.10.0",
        "crytic-compile>=0.3.0",
        "click>=8.0.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "delegateguard=analyzer.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.9",
    ],
)