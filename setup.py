from setuptools import find_packages, setup

setup(
    name="nexusosint",
    version="2.0.0",
    description="NexusOSINT - All-In-One Open-Source Intelligence & Chained Reconnaissance Framework",
    author="NexusOSINT Team",
    packages=find_packages(),
    py_modules=["osint"],
    install_requires=[
        "dnspython>=2.6.1",
        "pillow>=10.3.0",
        "phonenumbers>=8.13.38",
        "requests>=2.31.0",
        "rich>=13.7.1",
    ],
    entry_points={
        "console_scripts": [
            "nexusosint = nexus_osint.cli:main",
        ],
    },
    python_requires=">=3.10",
)
