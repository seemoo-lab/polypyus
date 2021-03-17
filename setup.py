from setuptools import find_packages, setup  # type: ignore

test_deps = ["coverage", "pytest", "hypothesis", "tox"]

setup(
    name="polypyus",
    version="1.1.0",
    python_requires=">=3.6",
    author="Jan Friebertshäuser",
    author_email="jfriebertshaeuser@seemoo.tu-darmstadt.de",
    packages=find_packages(),
    install_requires=[
        "pony == 0.7.*",
        "PyQt5 == 5.*",
        "PyQt5-sip",
        "pyelftools >= 0.25",
        "intervaltree == 3.*",
        "typer == 0.3.*",
        "loguru == 0.5.*",
        "tabulate == 0.8.*",
        'dataclasses; python_version<"3.7"',
    ],
    tests_require=test_deps,
    extras_require={
        "development": [
            "PyQt5-stubs == 5.*",
            "pylama",
            "pre-commit == 2.11.*",
            "black == 20.*",
        ],
        "test": test_deps,
    },
    package_data={
        "": ["style.css", "polypyus.ico", "Polypyus.png", "about.html", "LICENSE.txt"]
    },
    entry_points={
        "console_scripts": [
            "polypyus-cli=polypyus.cli:app",
            "polypyus-gui=polypyus.gui:app",
        ],
    },
)
