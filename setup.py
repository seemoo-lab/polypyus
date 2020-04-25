from setuptools import find_packages, setup

setup(
    name="polypyus",
    version="1.0",
    author="Jan Friebertshäuser",
    author_email="jfriebertshaeuser@seemoo.tu-darmstadt.de",
    packages=find_packages(),
    install_requires=[
        "pony == 0.7.*",
        "PyQt5 == 5.*",
        "PyQt5-sip",
        "pyelftools >= 0.25",
        "capstone == 4.0.*",
        "intervaltree == 3.*",
        "typer == 0.0.8",
        "loguru == 0.4.*",
        "tabulate == 0.8.*",
    ],
    package_data={
        "": ["style.css", "polypyus.ico", "Polypyus.png", "about.html", "LICENSE.txt"]
    },
    entry_points={
        "console_scripts": ["polypyus-cli=polypyus.cli:app"],
        "gui_scripts": ["polypyus=polypyus.gui:app"],
    },
)
