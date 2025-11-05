"""
Setup.py for backwards compatibility and broader distribution support.
"""
from setuptools import setup, find_packages

setup(
    name="impact-scan",
    use_scm_version={"fallback_version": "0.2.0"},
    setup_requires=["setuptools-scm"],
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "impact-scan=impact_scan.cli:app",
        ],
    },
    zip_safe=False,
    # All other metadata is in pyproject.toml
)