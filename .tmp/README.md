# Sandbox-only test helper

The sandboxed environment reports `/home` as `nobody:nogroup`, which the
broker correctly refuses as an untrusted socket ancestor. `run-tests.sh`
uses a broker-owned temp root so socket-based tests can run here.

Do not use this in production or normal development.
