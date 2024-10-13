from setuptools import setup, find_packages

setup(
    name='auth_shared',
    version='0.1',
    packages=find_packages(),  # Automatically find and include all packages in auth_shared/
    install_requires=[
        'PyJWT',  # Add your library dependencies here
        # e.g., 'Django>=3.2' or other requirements
    ],
    description='A shared authentication package for JWT-based microservices.',
    author='Jorge Fernandez Moreno',
    author_email='fernandezmorjorge@gmail.com',
    url='https://github.com/panesico/trancendence_auth_lib',  # Your GitHub repo
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)
