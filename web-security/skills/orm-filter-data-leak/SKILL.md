---
name: orm-filter-data-leak
description: Exploit ORM search/filter endpoints to leak data from joined/related tables via relationship traversal operators. Use when search, filter, or list endpoints are backed by an ORM (Django, Rails, Laravel, Sequelize, Hibernate).
---

# ORM Filter Data Leak

## Pattern
- Search/filter endpoints accepting field names or operators as parameters
- ORM-style syntax visible: double underscores `__`, dot notation, nested objects
- Response length or timing varies with different filter values
- Verbose errors revealing model/field names

## Probe
Traverse relationships to access fields from joined models:
```
GET /api/users?email__contains=a
GET /api/users?profile__ssn__startswith=1
GET /api/users?created_by__password__contains=a
GET /api/search?q[password_digest][startswith]=abc
```
Operators to try: `__contains`, `__startswith`, `__gt`, `__lt`, `__exact`, `__icontains`.
Chain through relations: `model__related_model__field__operator`.
Alternative syntax: `field[operator]=value`, `field.operator=value`.
Use boolean oracle (result count changes) or timing (collation-based `__gt`/`__lt`) to extract character-by-character.

## Indicators
- Response size changes reveal boolean oracle (matching vs non-matching records)
- Result count differs when filtering on fields that shouldn't be exposed
- Errors reveal ORM field names or relationship paths

## Chain With
- race-condition-single-packet (accelerate character-by-character extraction)

## Reference
https://www.elttam.com/blog/leaking-more-than-you-joined-for/
