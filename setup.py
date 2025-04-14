#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = f.read().splitlines()

setup(
    name="biocybe",
    version="0.1.0",
    author="BioCybe Team",
    author_email="contact@biocybe.org",
    description="Système de défense informatique bio-inspiré combinant IA et principes du système immunitaire",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/servais1983/biocybe",
    project_urls={
        "Bug Tracker": "https://github.com/servais1983/biocybe/issues",
        "Documentation": "https://github.com/servais1983/biocybe/docs",
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=requirements,
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "biocybe=biocybe.cli:main",
        ],
    },
)
