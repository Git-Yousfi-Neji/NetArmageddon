from setuptools import find_packages, setup

setup(
    name="netarmageddon",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.5.0",
        "PyYAML>=6.0.0",
        "rich>=12.0.0",
    ],
)
