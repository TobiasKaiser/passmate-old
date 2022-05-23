import setuptools

setuptools.setup(
    name="passmate_legacy",
    version="0.3",
    author="Tobias Kaiser",
    author_email="mail@tb-kaiser.de",
    description="Password manager",
    packages=setuptools.find_packages(),
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "passmate-legacy    = passmate_legacy.cli:main"
        ]
    }
)
