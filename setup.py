from setuptools import setup

setup(
    name='PacketAnalysis',
    version="1.0.3",
    packages=['PacketAnalysis'],
    install_requires=['scapy'],
    author="Maurice Lambert",
    author_email="mauricelambert434@gmail.com",
    maintainer="Maurice Lambert",
    maintainer_email="mauricelambert434@gmail.com",
    description="This package prints and sniffs the packets.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/mauricelambert/PacketAnalysis",
    project_urls = {
        "Sniffer doc": "https://mauricelambert.github.io/info/python/security/PacketAnalysis/Sniffer.html",
        "PacketPrinter doc": "https://mauricelambert.github.io/info/python/security/PacketAnalysis/PacketPrinter.html",
        "Executable": "https://mauricelambert.github.io/info/python/security/PacketAnalysis/PacketPrinter.pyz",
    },
    classifiers = [
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.9",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
    ],
    python_requires='>=3.6',
    entry_points = {
        'console_scripts': [
            'PacketAnalysis = PacketAnalysis:packets_analysis'
        ],
    },
    keywords=[
        "traffic",
        "network",
        "packet",
        "analysis",
    ],
    platforms=["Windows", "Linux", "MacOS"],
    license="GPL-3.0 License",
)