from setuptools import setup, find_packages

setup(
    name = 'PacketAnalysis',
 
    version = "0.0.1",
    packages = find_packages(include=["PacketAnalysis"]),
    install_requires = ['scapy'],

    author = "Maurice Lambert", 
    author_email = "mauricelambert434@gmail.com",
 
    description = "This package implement Packet Analysis with network sniffer or pcap file reader.",
    long_description = open('README.md').read(),
    long_description_content_type="text/markdown",
 
    include_package_data = True,

    url = 'https://github.com/mauricelambert/PacketAnalysis',
 
    classifiers = [
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.8"
    ],
 
    entry_points = {
        'console_scripts': [
            'PacketAnalysis = PacketAnalysis:packets_analysis'
        ],
    },
    python_requires='>=3.6',
)