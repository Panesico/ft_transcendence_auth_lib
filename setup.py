from setuptools import setup, find_packages
import codecs
import os

here = os.path.abspath(os.path.dirname(__file__))


VERSION = '0.0.11'
DESCRIPTION = 'A simple JWT middleware package'
LONG_DESCRIPTION = 'A simple JWT middleware package'

# Setting up
setup(
    name="authtranslib",
    version=VERSION,
    author="Jorge Fernandez Moreno",
    author_email="<fernandezmorjorge@gmail.com>",
    description=DESCRIPTION,
    long_description_content_type="text/markdown",
    long_description=LONG_DESCRIPTION,
    packages=find_packages(),
    install_requires=['pyjwt', 'django'],
    keywords=['python', 'auth', 'django'],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Operating System :: Unix",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
    ]
)