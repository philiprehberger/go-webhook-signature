# Changelog

## 0.2.0

- Fix middleware panic when `Content-Length` header is missing or chunked
- Fix middleware body reading to handle all transfer encodings correctly
- Restore request body after middleware verification so downstream handlers can read it
- Add comprehensive test suite

## 0.1.0

- Initial release
