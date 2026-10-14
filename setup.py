from setuptools import setup, find_packages

setup(
    name="capev2-report-generator",
    version="1.0.0",
    author="Nitiraj Kulkarni",
    description="Convert CAPEv2 Sandbox JSON analysis reports into publication-grade executive PDF reports with interactive GUI.",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "reportlab>=4.0.0",
        "pillow>=9.0.0",
        "customtkinter>=5.2.0",
        "darkdetect>=0.8.0",
    ],
    entry_points={
        "console_scripts": [
            "capev2-report=cape_report_generator.cli:run_cli",
            "cape-report=cape_report_generator.cli:run_cli",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
)
