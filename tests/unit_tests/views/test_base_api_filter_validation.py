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
"""Tests for API filter parameter validation (CWE-20)."""

import pytest

from superset.exceptions import InvalidPayloadFormatError
from superset.views.base_api import (
    _validate_filter_value,
    ALLOWED_FILTER_OPERATORS,
    MAX_FILTER_LIST_SIZE,
    MAX_FILTER_VALUE_LENGTH,
    validate_api_filters,
)


class TestAllowedFilterOperators:
    def test_valid_operators_in_allowlist(self) -> None:
        expected = {
            "sw", "nsw", "ew", "new", "ct", "nct",
            "eq", "neq", "gt", "lt", "in", "not_in",
            "rel_o_m", "nrel_o_m", "rel_m_m", "eqf", "inf",
        }
        assert ALLOWED_FILTER_OPERATORS == expected

    def test_allowlist_is_frozen(self) -> None:
        assert isinstance(ALLOWED_FILTER_OPERATORS, frozenset)


class TestValidateFilterValue:
    def test_valid_string(self) -> None:
        _validate_filter_value("hello")

    def test_valid_integer(self) -> None:
        _validate_filter_value(42)

    def test_valid_float(self) -> None:
        _validate_filter_value(3.14)

    def test_valid_boolean(self) -> None:
        _validate_filter_value(True)

    def test_valid_list(self) -> None:
        _validate_filter_value(["a", "b", "c"])

    def test_string_exceeding_max_length(self) -> None:
        with pytest.raises(InvalidPayloadFormatError):
            _validate_filter_value("x" * (MAX_FILTER_VALUE_LENGTH + 1))

    def test_string_at_max_length(self) -> None:
        _validate_filter_value("x" * MAX_FILTER_VALUE_LENGTH)

    def test_list_exceeding_max_size(self) -> None:
        with pytest.raises(InvalidPayloadFormatError):
            _validate_filter_value(["a"] * (MAX_FILTER_LIST_SIZE + 1))

    def test_list_at_max_size(self) -> None:
        _validate_filter_value(["a"] * MAX_FILTER_LIST_SIZE)

    def test_list_item_exceeding_max_length(self) -> None:
        with pytest.raises(InvalidPayloadFormatError):
            _validate_filter_value(["x" * (MAX_FILTER_VALUE_LENGTH + 1)])

    def test_list_with_invalid_type(self) -> None:
        with pytest.raises(InvalidPayloadFormatError):
            _validate_filter_value([{"nested": "dict"}])

    def test_invalid_type_dict(self) -> None:
        with pytest.raises(InvalidPayloadFormatError):
            _validate_filter_value({"key": "value"})

    def test_invalid_type_none(self) -> None:
        with pytest.raises(InvalidPayloadFormatError):
            _validate_filter_value(None)


class TestValidateApiFilters:
    def test_valid_filter(self) -> None:
        filters = [{"col": "name", "opr": "eq", "value": "test"}]
        validate_api_filters(filters)

    def test_valid_filter_with_list_value(self) -> None:
        filters = [{"col": "id", "opr": "in", "value": [1, 2, 3]}]
        validate_api_filters(filters)

    def test_invalid_operator(self) -> None:
        filters = [
            {"col": "name", "opr": "INVALID", "value": "t"},
        ]
        with pytest.raises(
            InvalidPayloadFormatError,
            match="Invalid filter",
        ):
            validate_api_filters(filters)

    def test_empty_column_name(self) -> None:
        filters = [
            {"col": "", "opr": "eq", "value": "test"},
        ]
        with pytest.raises(
            InvalidPayloadFormatError,
            match="Invalid filter",
        ):
            validate_api_filters(filters)

    def test_column_name_too_long(self) -> None:
        filters = [
            {"col": "x" * 201, "opr": "eq", "value": "t"},
        ]
        with pytest.raises(
            InvalidPayloadFormatError,
            match="Invalid filter",
        ):
            validate_api_filters(filters)

    def test_missing_col_field(self) -> None:
        filters = [{"opr": "eq", "value": "test"}]
        with pytest.raises(
            InvalidPayloadFormatError,
            match="Invalid filter",
        ):
            validate_api_filters(filters)

    def test_missing_opr_field(self) -> None:
        filters = [{"col": "name", "value": "test"}]
        with pytest.raises(
            InvalidPayloadFormatError,
            match="Invalid filter",
        ):
            validate_api_filters(filters)

    def test_value_too_long(self) -> None:
        long = "x" * (MAX_FILTER_VALUE_LENGTH + 1)
        filters = [
            {"col": "name", "opr": "ct", "value": long},
        ]
        with pytest.raises(
            InvalidPayloadFormatError,
            match="maximum length",
        ):
            validate_api_filters(filters)

    def test_multiple_valid_filters(self) -> None:
        filters = [
            {"col": "name", "opr": "ct", "value": "test"},
            {"col": "id", "opr": "gt", "value": 5},
            {"col": "s", "opr": "in", "value": ["a"]},
        ]
        validate_api_filters(filters)

    def test_sql_injection_in_operator(self) -> None:
        filters = [
            {
                "col": "name",
                "opr": "eq; DROP TABLE users;--",
                "value": "test",
            },
        ]
        with pytest.raises(InvalidPayloadFormatError):
            validate_api_filters(filters)

    def test_empty_filter_list(self) -> None:
        validate_api_filters([])
