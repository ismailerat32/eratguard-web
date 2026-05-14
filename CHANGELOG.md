# Changelog

## v1.0.0-beta - 2026-05-14

### Added
- EratGuard PRO brand migration started.
- New dark splash and login UI added.
- Turkish spam dataset added.
- AI spam model improved and retrained.
- Android user APK build prepared.
- Runtime project status documented in DURUM.md.

### Changed
- SECRET_KEY and ADMIN_PASSWORD moved to environment variables.
- requirements.txt cleaned for release readiness.
- .gitignore expanded to protect runtime, user, token, license, database and log files.
- Spam model updated with larger vocabulary and training dataset.

### Security
- Removed runtime/user data files from Git tracking.
- Protected local files such as users, reset tokens, generated licenses, quarantine records, payment requests and event logs from being committed.

### Known Issues
- Admin APK rebrand is still pending.
- User radial menu needs restoration.
- APK release build is still pending; current APK is debug.
- Admin session redirect issue needs verification.
