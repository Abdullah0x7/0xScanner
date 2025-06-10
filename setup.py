#!/usr/bin/env python3
"""
Setup script for 0xScanner
Professional installation and packaging
"""

from setuptools import setup, find_packages
import pathlib

# Read the README file
HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name="0xscanner",
    version="2.0.0",
    description="Professional Network Port Scanner for Security Professionals",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/Abdullah0x7/0xScanner",
    author="Abdullah Bello",
    author_email="belloabdullah76@gmail.com",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators", 
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    keywords="security networking port-scanner penetration-testing cybersecurity",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        # No external dependencies - uses only Python standard library
    ],
    extras_require={
        "enhanced": [
            "colorama>=0.4.4",
            "rich>=12.0.0",
        ],
        "dev": [
            "pytest>=6.2.0",
            "pytest-asyncio>=0.15.0",
            "black>=21.0.0",
            "flake8>=3.9.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "0xscanner=0xscanner.scanner:main",
        ],
    },
    include_package_data=True,
    project_urls={
        "Bug Reports": "https://github.com/Abdullah0x7/0xScanner/issues",
        "Source": "https://github.com/Abdullah0x7/0xScanner",
        "Documentation": "https://github.com/Abdullah0x7/0xScanner/blob/main/README.md",
    },
)