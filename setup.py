from setuptools import find_packages, setup

setup(
    name="nexusosint",
    version="2.0.0",
    description="NexusOSINT - All-In-One Open-Source Intelligence & Chained Reconnaissance Framework",
    author="NexusOSINT Team",
    packages=find_packages(),
    py_modules=["osint"],
    install_requires=[
        "dnspython>=2.6.0",
        "exifread>=3.0.0",
        "httpx>=0.27.0",
        "phonenumbers>=8.13.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "nexusosint = nexus_osint.cli:main",
        ],
    },
    python_requires=">=3.10",
)
