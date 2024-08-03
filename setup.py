from setuptools import setup, find_packages

setup(
    name='TGxss07',
    version='1.0',
    description='XSS Vulnerability Finder Tool',
    author='Your Name',
    author_email='your.email@example.com',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'tgxss07=tgxss07.tgxss07:main',
        ],
    },
    install_requires=[
        'requests',
        'beautifulsoup4',
        'termcolor',
    ],
    python_requires='>=3.6',
)
