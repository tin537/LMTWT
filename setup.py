from setuptools import setup, find_packages

setup(
    name="lmtwt",
    version="0.1.0",
    description="Language Model Testing With Triangulation - AI prompt injection testing tool",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "google-generativeai>=0.3.0",
        "openai>=1.0.0",
        "anthropic>=0.5.0", 
        "requests>=2.28.0",
        "python-dotenv>=1.0.0",
        "colorama>=0.4.6",
        "rich>=13.0.0",
        "tiktoken>=0.4.0",
    ],
    entry_points={
        "console_scripts": [
            "lmtwt=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security :: Penetration Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
) 