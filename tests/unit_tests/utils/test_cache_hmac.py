# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from unittest.mock import MagicMock, patch

import pytest

from superset.utils.cache import (
    _compute_cache_hmac,
    CACHE_HMAC_KEY,
    verify_cache_value,
)


@pytest.fixture
def mock_app():
    app = MagicMock()
    app.config = {"SECRET_KEY": "test-secret-key-1234"}
    with patch("superset.utils.cache.app", app):
        yield app


def test_compute_cache_hmac_deterministic():
    """HMAC computation is deterministic for the same inputs."""
    value = {"foo": "bar", "num": 42}
    h1 = _compute_cache_hmac("key1", value, "secret")
    h2 = _compute_cache_hmac("key1", value, "secret")
    assert h1 == h2


def test_compute_cache_hmac_changes_with_key():
    """Different cache keys produce different HMACs."""
    value = {"foo": "bar"}
    h1 = _compute_cache_hmac("key1", value, "secret")
    h2 = _compute_cache_hmac("key2", value, "secret")
    assert h1 != h2


def test_compute_cache_hmac_changes_with_value():
    """Different values produce different HMACs."""
    h1 = _compute_cache_hmac("key", {"a": 1}, "secret")
    h2 = _compute_cache_hmac("key", {"a": 2}, "secret")
    assert h1 != h2


def test_compute_cache_hmac_changes_with_secret():
    """Different secrets produce different HMACs."""
    value = {"foo": "bar"}
    h1 = _compute_cache_hmac("key", value, "secret1")
    h2 = _compute_cache_hmac("key", value, "secret2")
    assert h1 != h2


def test_compute_cache_hmac_ignores_hmac_field():
    """The HMAC field itself is excluded from computation."""
    value = {"foo": "bar"}
    value_with_hmac = {"foo": "bar", CACHE_HMAC_KEY: "stale"}
    h1 = _compute_cache_hmac("key", value, "secret")
    h2 = _compute_cache_hmac("key", value_with_hmac, "secret")
    assert h1 == h2


def test_compute_cache_hmac_handles_non_serializable(mock_app):
    """Non-JSON-serializable values are reduced to their type name."""
    value = {"data": object()}
    hmac_val = _compute_cache_hmac("key", value, "secret")
    assert isinstance(hmac_val, str)
    assert len(hmac_val) == 64


def test_verify_cache_value_valid(mock_app):
    """A correctly signed value passes verification."""
    cache_key = "test-key"
    value = {"data": "hello", "dttm": "2024-01-01T00:00:00"}
    value[CACHE_HMAC_KEY] = _compute_cache_hmac(
        cache_key, value, "test-secret-key-1234"
    )

    result = verify_cache_value(cache_key, value)
    assert result is not None
    assert result["data"] == "hello"
    assert CACHE_HMAC_KEY not in result


def test_verify_cache_value_tampered(mock_app):
    """A value with modified payload fails verification."""
    cache_key = "test-key"
    value = {"data": "hello", "dttm": "2024-01-01T00:00:00"}
    value[CACHE_HMAC_KEY] = _compute_cache_hmac(
        cache_key, value, "test-secret-key-1234"
    )
    # tamper with the payload
    value["data"] = "malicious"

    result = verify_cache_value(cache_key, value)
    assert result is None


def test_verify_cache_value_wrong_key(mock_app):
    """A value verified against a different cache key fails."""
    value = {"data": "hello", "dttm": "2024-01-01T00:00:00"}
    value[CACHE_HMAC_KEY] = _compute_cache_hmac(
        "original-key", value, "test-secret-key-1234"
    )

    result = verify_cache_value("different-key", value)
    assert result is None


def test_verify_cache_value_legacy_no_hmac(mock_app):
    """Legacy cache entries without HMAC are allowed with a warning."""
    value = {"data": "old-entry", "dttm": "2023-01-01T00:00:00"}

    result = verify_cache_value("some-key", value)
    assert result is not None
    assert result["data"] == "old-entry"


def test_verify_cache_value_none(mock_app):
    """None input returns None."""
    assert verify_cache_value("key", None) is None


def test_verify_cache_value_non_dict(mock_app):
    """Non-dict input returns None."""
    assert verify_cache_value("key", "not-a-dict") is None  # type: ignore[arg-type]
