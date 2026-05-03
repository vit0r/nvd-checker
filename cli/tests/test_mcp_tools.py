import json
import os
from unittest.mock import patch, MagicMock

import pytest

from mcp_server.tools import (
    check_dependency,
    list_supported_ecosystems,
    scan_repository,
)


@pytest.fixture
def mock_nvd_client():
    with patch("mcp_server.tools.NVDClient") as mock:
        yield mock


@pytest.fixture
def mock_dependency_detector():
    with patch("mcp_server.tools.DependencyDetector") as mock:
        yield mock


def test_list_supported_ecosystems():
    """Test list_supported_ecosystems tool."""
    result_str = list_supported_ecosystems()
    result = json.loads(result_str)
    
    assert result["status"] == "success"
    assert "python" in result["ecosystems"]
    assert "nodejs" in result["ecosystems"]


def test_check_dependency_no_vulnerabilities(mock_nvd_client):
    """Test check_dependency when no vulnerabilities are found."""
    # Setup mock
    client_instance = mock_nvd_client.return_value
    
    # We also need to mock the VulnerabilityMatcher
    with patch("mcp_server.tools.VulnerabilityMatcher") as mock_matcher:
        matcher_instance = mock_matcher.return_value
        
        # Create a mock result
        mock_result = MagicMock()
        mock_result.is_vulnerable = False
        mock_result.cves = []
        mock_result.dependency.name = "requests"
        mock_result.dependency.version = "2.32.0"
        mock_result.max_severity = "NONE"
        mock_result.max_score = 0.0
        
        matcher_instance.check_dependency.return_value = mock_result
        
        # Call the tool
        result_str = check_dependency("requests", "2.32.0")
        result = json.loads(result_str)
        
        assert result["status"] == "success"
        assert result["package"] == "requests"
        assert result["is_vulnerable"] is False
        assert result["total_cves"] == 0
        assert len(result["vulnerabilities"]) == 0


def test_scan_repository_invalid_path():
    """Test scan_repository with a non-existent path."""
    result_str = scan_repository("/path/does/not/exist/12345")
    result = json.loads(result_str)
    
    assert result["status"] == "error"
    assert "Path does not exist" in result["message"]
