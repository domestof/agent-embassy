"""Fixed core fields per catalog @type. The spec (section 4) already decided
the *mechanism* — a fixed core schema per type, plus schema.org's own
`additionalProperty` (PropertyValue array) as the escape hatch for anything
else — this module just enumerates the actual field lists, deliberately
minimal (matching the placeholder JSON already in static/catalog/). Anything
a pilot admin wants beyond these goes through additionalProperty, not a new
per-type field added here — that's what keeps this "no new mechanism."
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    input_type: str  # "text" or "textarea"
    required: bool = False


# kind (URL/file segment) -> fixed @type for that catalog file.
KINDS: dict[str, str] = {
    "products": "Product",
    "services": "Service",
    "jobs": "JobPosting",
    "demand": "Demand",
}

CORE_FIELDS: dict[str, list[Field]] = {
    "Product": [
        Field("name", "Name", "text", required=True),
        Field("description", "Description", "textarea"),
        Field("sku", "SKU", "text"),
        Field("url", "URL", "text"),
    ],
    "Service": [
        Field("name", "Name", "text", required=True),
        Field("description", "Description", "textarea"),
        Field("url", "URL", "text"),
    ],
    "JobPosting": [
        Field("title", "Title", "text", required=True),
        Field("description", "Description", "textarea"),
        Field("employmentType", "Employment type", "text"),
        Field("url", "URL", "text"),
    ],
    "Demand": [
        Field("name", "Name", "text", required=True),
        Field("description", "Description", "textarea"),
        Field("url", "URL", "text"),
    ],
}


class InvalidItem(ValueError):
    pass


def core_field_names(item_type: str) -> set[str]:
    return {f.name for f in CORE_FIELDS[item_type]}


def validate_item(item: dict) -> None:
    """Raises InvalidItem if `item` doesn't satisfy its own @type's fixed
    core schema. Does not touch unrecognized fields — preserving those on
    round-trip is catalog_store's job, not this function's."""
    item_type = item.get("@type")
    if item_type not in CORE_FIELDS:
        raise InvalidItem(f"unrecognized @type {item_type!r}")

    for field in CORE_FIELDS[item_type]:
        if field.required and not str(item.get(field.name, "")).strip():
            raise InvalidItem(f"{field.label} is required")

    for prop in item.get("additionalProperty", []):
        if prop.get("@type") != "PropertyValue" or not str(prop.get("name", "")).strip():
            raise InvalidItem("each additional property needs a name")


def item_from_form(item_type: str, form: dict, existing: dict | None = None) -> dict:
    """Build a catalog item from submitted form fields. Starts from
    `existing` (if editing) so any field the UI doesn't know about survives
    untouched — only the recognized core fields and additionalProperty are
    ever overwritten."""
    item = dict(existing) if existing else {}
    item["@type"] = item_type

    for field in CORE_FIELDS[item_type]:
        value = form.get(f"field__{field.name}", "").strip()
        if value:
            item[field.name] = value
        else:
            item.pop(field.name, None)

    names = form.getlist("extra_name") if hasattr(form, "getlist") else form.get("extra_name", [])
    values = form.getlist("extra_value") if hasattr(form, "getlist") else form.get("extra_value", [])
    additional = [
        {"@type": "PropertyValue", "name": name.strip(), "value": value.strip()}
        for name, value in zip(names, values)
        if name.strip()
    ]
    if additional:
        item["additionalProperty"] = additional
    else:
        item.pop("additionalProperty", None)

    return item
