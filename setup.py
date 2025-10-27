# setup.py
from setuptools import setup, find_packages

setup(
    name="task-manager",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "Flask",
        "Flask-SQLAlchemy",
        "Flask-WTF", 
        "Flask-JWT-Extended",
    ],
)