from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="protection-scanner",
    version="2.0.0",
    author="HACKER",
    author_email="your-email@example.com",
    description="Advanced website protection scanning tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/protection-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "protectionscanner=protection_scanner:main",
        ],
    },
)