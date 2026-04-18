"""
setup.py — install the forensic agent as the `forensic-agent` command.

Usage (from the repo root):
    cd agent
    pip install -e .
    forensic-agent --help

Cross-platform: pure Python, tested on macOS and Windows.
"""

from setuptools import setup

setup(
    name="forensic-agent",
    version="1.0.0",
    description="CLI agent for the Digital Forensics Investigation Platform.",
    long_description=(
        "Uploads disk images or directories from an investigator's machine "
        "to the backend for Sleuth Kit analysis and retrieves the PDF report."
    ),
    py_modules=["forensic_agent"],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.0",
        "requests>=2.31.0",
        "tqdm>=4.66.0",
    ],
    entry_points={
        "console_scripts": [
            "forensic-agent=forensic_agent:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
