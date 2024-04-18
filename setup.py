from setuptools import setup, find_packages


def read_requirements():
    with open("requirements.txt") as req:
        content = req.read()
        requirements = content.split("\n")

    return requirements


with open("README.md", "r") as f:
    description = f.read()

setup(
    name="repelsec",
    version="0.6",
    packages=find_packages(),
    include_package_data=True,
    install_requires=read_requirements(),
    entry_points='''
    [console_scripts]
    repelsec=repelsec.main:main
    ''',
    long_description=description,
    long_description_content_type="text/markdown",
)
