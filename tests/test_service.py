import pytest
import tempfile
import os
import json
from unittest.mock import patch, MagicMock
import sys
import io
from werkzeug.datastructures import FileStorage

# Import the app module
from yarobot.service import app, initialize_databases, AnalysisRequest, save_uploaded_files

from python.yarobot.service import init_context


@pytest.fixture
def client():
    """Create a test client for the Flask app"""
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_client() as client:
        yield client


@pytest.fixture
def mock_databases():
    """Mock the database initialization"""
    with patch("yarobot.service.DATABASES", ({}, {}, {}, {})):
        with patch("yarobot.service.PESTUDIO_STRINGS", {}):
            yield


class TestAnalysisRequest:
    """Test the AnalysisRequest class"""

    @pytest.mark.unit
    def test_default_parameters(self):
        """Test that default parameters are set correctly"""
        args = AnalysisRequest({})

        assert args.min_size == 8
        # assert args.min_score == 5
        assert args.high_scoring == 30
        assert args.max_size == 128
        assert args.strings_per_rule == 15
        assert args.excludegood is False
        assert args.author == "yarobot HTTP Service"


class TestFileHandling:
    """Test file handling utilities"""

    @pytest.mark.unit
    def test_save_uploaded_files(self):
        """Test saving uploaded files to temporary directory"""
        from werkzeug.datastructures import FileStorage

        mock_file1 = FileStorage(stream=io.BytesIO(b"test content 1"), filename="test1.exe")
        mock_file2 = FileStorage(stream=io.BytesIO(b"test content 2"), filename="test2.dll")

        files = [mock_file1, mock_file2]

        temp_dir = save_uploaded_files(files)

        try:
            assert os.path.exists(temp_dir)
            assert os.path.isdir(temp_dir)

            saved_files = os.listdir(temp_dir)
            assert "test1.exe" in saved_files
            assert "test2.dll" in saved_files

        finally:
            import shutil

            shutil.rmtree(temp_dir)


class TestHealthEndpoints:
    """Test health and status endpoints"""

    @pytest.mark.http
    def test_health_check(self, client, mock_databases):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "healthy"

    @pytest.mark.http
    def test_status_endpoint(self, client, mock_databases):
        """Test status endpoint"""
        response = client.get("/api/status")
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "running"


class TestAnalyzeEndpoint:
    """Test the main analyze endpoint"""

    @pytest.fixture
    def sample_file(self):
        """Create a sample test file"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
            f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xffaaaaaaaaaaaaaaaaaaaaa" * 35)
            f.flush()
            yield f.name
        if os.path.exists(f.name):
            os.unlink(f.name)

    @pytest.mark.integration
    def test_single_file_analysis(self, sample_file, client):
        """Test analysis with single file"""
        # Mock the process_folder to return sample rules
        # mock_process.return_value = "rule TestRule { condition: true }"
        # initialize_databases()
        with open(sample_file, "rb") as f:
            # print(f.read())
            file_storage = FileStorage(stream=f, filename="test_file.txt", content_type="text/plain")
            response = client.post(
                "/api/analyze",
                data={"files": file_storage, "min_score": "0", "get_opcodes": "true"},
            )

        # This should be a real Flask response, not a mock
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "success"
        assert data["rules_generated"] is True
        assert data["rules_count"] == 1
        print(data["rules_content"])

        # Verify the mock was called
        # mock_process.assert_called_once()

    @pytest.mark.http
    def test_no_files_provided(self, client, mock_databases):
        """Test request with no files"""
        response = client.post("/api/analyze")
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "No files provided"

    @pytest.mark.http
    def test_empty_files_list(self, client, mock_databases):
        """Test request with empty files list"""
        # Create empty files list
        response = client.post("/api/analyze", data={"files": ""})
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data["error"] == "No files provided"

    @pytest.mark.http
    @patch("yarobot.generate.process_folder")
    def test_invalid_parameter_types(self, mock_process, client, mock_databases, sample_file):
        """Test analysis with invalid parameter types"""
        with open(sample_file, "rb") as f:
            response = client.post("/api/analyze", data={"files": (f, "test.exe"), "min_score": "invalid_number"})

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data


class TestErrorHandlers:
    """Test error handlers"""

    @pytest.mark.http
    def test_404_not_found(self, client, mock_databases):
        """Test 404 error handling"""
        response = client.get("/nonexistent_endpoint")
        assert response.status_code == 404

    @pytest.mark.http
    def test_method_not_allowed(self, client, mock_databases):
        """Test 405 error handling"""
        response = client.put("/api/analyze")
        assert response.status_code == 405
