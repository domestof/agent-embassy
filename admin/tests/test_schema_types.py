import pytest

import schema_types


class _FakeForm(dict):
    def getlist(self, key):
        return self.get(key, [])


def test_core_fields_cover_all_kinds():
    for item_type in schema_types.KINDS.values():
        assert item_type in schema_types.CORE_FIELDS


def test_each_type_has_a_required_field():
    for item_type, fields in schema_types.CORE_FIELDS.items():
        assert any(f.required for f in fields), f"{item_type} has no required field"


def test_validate_item_rejects_missing_required_field():
    with pytest.raises(schema_types.InvalidItem):
        schema_types.validate_item({"@type": "Product", "description": "no name"})


def test_validate_item_rejects_unknown_type():
    with pytest.raises(schema_types.InvalidItem):
        schema_types.validate_item({"@type": "NotARealType", "name": "x"})


def test_validate_item_accepts_minimal_valid_item():
    schema_types.validate_item({"@type": "Product", "name": "Widget"})  # does not raise


def test_validate_item_rejects_additional_property_without_name():
    item = {"@type": "Product", "name": "Widget", "additionalProperty": [{"@type": "PropertyValue", "value": "x"}]}
    with pytest.raises(schema_types.InvalidItem):
        schema_types.validate_item(item)


def test_item_from_form_preserves_unrecognized_fields_on_edit():
    existing = {"@type": "Product", "name": "Old", "customField": "keep-me"}
    form = _FakeForm({"field__name": "New", "field__description": ""})

    item = schema_types.item_from_form("Product", form, existing=existing)
    assert item["name"] == "New"
    assert item["customField"] == "keep-me"


def test_item_from_form_drops_blanked_optional_field():
    existing = {"@type": "Product", "name": "Old", "sku": "ABC"}
    form = _FakeForm({"field__name": "Old", "field__sku": ""})

    item = schema_types.item_from_form("Product", form, existing=existing)
    assert "sku" not in item


def test_item_from_form_builds_additional_property_from_rows():
    form = _FakeForm({"field__name": "Widget", "extra_name": ["color", ""], "extra_value": ["blue", "ignored"]})
    item = schema_types.item_from_form("Product", form)
    assert item["additionalProperty"] == [{"@type": "PropertyValue", "name": "color", "value": "blue"}]
