from setuptools import setup, find_packages

setup(
    name="netarmageddon",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "PyYAML>=6.0.0",
    ],
)