from setuptools import setup, find_packages

setup(
    name='oregami',
    version='1.0.0',
    packages=find_packages(),
    url='https://github.com/shemesh999/oregami',
    license='MIT',
    author='Matan Ziv',
    description='IDA plugins and scripts for analyzing register usage frame',

    install_requires=[
        'sark', 'cachetools'
    ],
)
