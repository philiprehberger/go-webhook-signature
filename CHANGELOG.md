# Changelog

## 0.3.3

- Standardize README to 3-badge format with emoji Support section
- Update CI checkout action to v5 for Node.js 24 compatibility
- Add GitHub issue templates, dependabot config, and PR template

## 0.3.2

- Consolidate README badges onto single line

## 0.3.1

- Add badges and Development section to README

## 0.3.0

- Fix `ParseHeader` accepting empty `sha256=` value as valid signature

## 0.2.0

- Fix middleware panic when `Content-Length` header is missing or chunked
- Fix middleware body reading to handle all transfer encodings correctly
- Restore request body after middleware verification so downstream handlers can read it
- Add comprehensive test suite

## 0.1.0

- Initial release
