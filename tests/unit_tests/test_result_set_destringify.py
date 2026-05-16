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
from superset.result_set import _is_safe_json_value, destringify


def test_destringify_dict():
    assert destringify('{"a": 1, "b": "two"}') == {"a": 1, "b": "two"}


def test_destringify_list():
    assert destringify('[1, 2, "three"]') == [1, 2, "three"]


def test_destringify_string():
    assert destringify('"hello"') == "hello"


def test_destringify_number():
    assert destringify("42") == 42


def test_destringify_null():
    assert destringify("null") is None


def test_destringify_nested():
    result = destringify('{"rows": [{"id": 1}, {"id": 2}]}')
    assert result == {"rows": [{"id": 1}, {"id": 2}]}


def test_is_safe_json_value_primitives():
    assert _is_safe_json_value("str") is True
    assert _is_safe_json_value(1) is True
    assert _is_safe_json_value(1.5) is True
    assert _is_safe_json_value(True) is True
    assert _is_safe_json_value(None) is True


def test_is_safe_json_value_containers():
    assert _is_safe_json_value({"a": 1}) is True
    assert _is_safe_json_value([1, "two", None]) is True
    assert _is_safe_json_value({"nested": {"list": [1, 2]}}) is True


def test_is_safe_json_value_rejects_unsafe():
    assert _is_safe_json_value(object()) is False
    assert _is_safe_json_value(set()) is False
    assert _is_safe_json_value(b"bytes") is False
    assert _is_safe_json_value({"ok": 1, "bad": object()}) is False
    assert _is_safe_json_value([1, object()]) is False
