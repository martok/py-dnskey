#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="dnskeytool",
    version="0.3.0",
    author="Martok",
    author_email="martok@martoks-place.de",
    description="Simple tool for DNSSEC key management",
    license="MIT",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking",
    ],
    entry_points={
        'console_scripts': ['dnskeytool=dnskeytool.shell:main'],
    },
    package_dir={
        "": "src"
    },
    packages=find_packages(where="src"),
    install_requires=[
        "dnspython",
    ],
    python_requires=">=3.7",
)
