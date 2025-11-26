import os
from pathlib import Path
from typing import Iterator, List, Set

import pathspec

# Define common code file extensions for discoverability
PYTHON_EXTENSIONS = {".py"}
JAVASCRIPT_EXTENSIONS = {".js", ".jsx"}
TYPESCRIPT_EXTENSIONS = {".ts", ".tsx"}
CODE_EXTENSIONS = PYTHON_EXTENSIONS | JAVASCRIPT_EXTENSIONS | TYPESCRIPT_EXTENSIONS

# Define common configuration file names for project type detection
PYTHON_CONFIG_FILES = {"requirements.txt", "pyproject.toml", "setup.py"}
NODE_CONFIG_FILES = {"package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json"}


def discover_files(root_path: Path, extensions: Set[str]) -> Iterator[Path]:
    """
    Discovers files with specified extensions, respecting .gitignore rules.

    Args:
        root_path: The root directory to start the search from.
        extensions: A set of file extensions to look for (e.g., {".py"}).

    Yields:
        An iterator of Path objects for the discovered files.

    Raises:
        NotADirectoryError: If the provided root_path is not a directory.
    """
    if not root_path.is_dir():
        raise NotADirectoryError(f"Provided path is not a directory: {root_path}")

    # 1. Find all .gitignore files and read their patterns
    gitignore_files = root_path.rglob(".gitignore")
    patterns = []
    for gitignore_file in gitignore_files:
        with gitignore_file.open("r") as f:
            patterns.extend(f.readlines())

    spec = pathspec.PathSpec.from_lines("gitwildmatch", patterns)

    # 2. Walk the directory and yield files that are not ignored
    for dirpath, _, filenames in os.walk(str(root_path)):
        for filename in filenames:
            file_path = Path(dirpath) / filename
            # Use relative path for matching against the spec
            relative_path = file_path.relative_to(root_path)

            if not spec.match_file(str(relative_path)):
                if file_path.suffix in extensions:
                    yield file_path


def read_file_content(file_path: Path) -> str:
    """
    Safely reads the content of a file using UTF-8 encoding.

    Args:
        file_path: The path to the file to read.

    Returns:
        The content of the file as a string.

    Raises:
        FileNotFoundError: If the file does not exist at the given path.
        IOError: If the file cannot be read due to permissions or other issues.
        UnicodeDecodeError: If the file is not encoded in valid UTF-8.
    """
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found at path: {file_path}")

    try:
        return file_path.read_text(encoding="utf-8")
    except (IOError, UnicodeDecodeError) as e:
        raise e


def find_project_configs(root_path: Path, config_filenames: Set[str]) -> List[Path]:
    """
    Finds specific configuration files in the project root directory.

    Args:
        root_path: The root directory of the project.
        config_filenames: A set of filenames to search for.

    Returns:
        A list of Path objects for the found configuration files.

    Raises:
        NotADirectoryError: If the provided root_path is not a directory.
    """
    if not root_path.is_dir():
        raise NotADirectoryError(f"Provided path is not a directory: {root_path}")

    found_files: List[Path] = []
    for filename in config_filenames:
        file_path = root_path / filename
        if file_path.is_file():
            found_files.append(file_path)
    return found_files
