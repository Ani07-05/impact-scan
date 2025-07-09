from pathlib import Path
from unittest.mock import MagicMock

from impact_scan.core import entrypoint
from impact_scan.utils import schema


# ... (keep the test_flask_detector tests as they were) ...
def test_flask_detector_finds_app(mocker):
    """
    Tests that the FlaskDetector correctly identifies a file containing 'Flask(__name__)'.
    """
    # Mock the filesystem interaction
    mock_discover_files = mocker.patch("impact_scan.core.entrypoint.paths.discover_files")
    mock_read_content = mocker.patch("impact_scan.core.entrypoint.paths.read_file_content")

    # Setup mock return values
    mock_file = Path("/app/main.py")
    mock_discover_files.return_value = [mock_file]
    mock_read_content.return_value = "from flask import Flask\n\napp = Flask(__name__)"

    # Run the detector
    detector = entrypoint.FlaskDetector()
    results = list(detector.detect(Path("/app")))

    # Assert the outcome
    assert len(results) == 1
    assert results[0].path == mock_file
    assert results[0].framework == "Flask"
    assert results[0].confidence == 0.9
    mock_discover_files.assert_called_once_with(Path("/app"), {".py"})
    mock_read_content.assert_called_once_with(mock_file)


def test_flask_detector_finds_main_block(mocker):
    """
    Tests that the FlaskDetector correctly identifies a file with a __main__ block.
    """
    mock_discover_files = mocker.patch("impact_scan.core.entrypoint.paths.discover_files")
    mock_read_content = mocker.patch("impact_scan.core.entrypoint.paths.read_file_content")

    mock_file = Path("/app/run.py")
    mock_discover_files.return_value = [mock_file]
    mock_read_content.return_value = "def main():\n    print('hello')\n\nif __name__ == '__main__':\n    main()"

    detector = entrypoint.FlaskDetector()
    results = list(detector.detect(Path("/app")))

    assert len(results) == 1
    assert results[0].path == mock_file
    assert results[0].framework == "Python Executable"
    assert results[0].confidence == 0.7


def test_nextjs_detector_finds_canonical_path(mocker):
    """
    Tests that the NextJSDetector correctly identifies a canonical Next.js file.
    """
    mock_is_file = mocker.patch("pathlib.Path.is_file")

    # FIX: The side_effect function receives the Path instance as `self`.
    def side_effect(self):
        return str(self) == "/project/src/app/page.tsx"

    mock_is_file.side_effect = side_effect

    detector = entrypoint.NextJSDetector()
    results = list(detector.detect(Path("/project")))

    assert len(results) == 1
    assert results[0].path == Path("/project/src/app/page.tsx")


def test_find_entry_points_aggregates_results(mocker):
    """
    Tests that the main function aggregates results from all registered detectors.
    """
    mock_flask_detector = MagicMock()
    mock_nextjs_detector = MagicMock()

    flask_entry = schema.EntryPoint(path=Path("f.py"), framework="Flask", confidence=0.9)
    nextjs_entry = schema.EntryPoint(path=Path("n.js"), framework="Next.js", confidence=1.0)

    mock_flask_detector.detect.return_value = [flask_entry]
    mock_nextjs_detector.detect.return_value = [nextjs_entry]

    # FIX: The patch now correctly targets the module-level variable.
    mocker.patch(
        "impact_scan.core.entrypoint.DETECTORS",
        [mock_flask_detector, mock_nextjs_detector]
    )

    results = entrypoint.find_entry_points(Path("/any"))

    assert len(results) == 2
    assert flask_entry in results
    assert nextjs_entry in results
