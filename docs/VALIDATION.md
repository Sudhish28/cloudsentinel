# Validation record

Validated locally on Windows with Python 3.12 and Node 24 on 2026-09-05.

- 11 pytest tests passed against SQLite.
- React/Vite production build passed using the native config loader.
- Live Uvicorn smoke test: 36 synthetic events accepted; replay skipped all 36 duplicates.
- Stored statistics: 36 events with findings, including 3 high-severity events.
- Dashboard returned HTTP 200; unauthenticated alert API returned HTTP 401.
- Template incident summary returned successfully.
- Mocked LLM success and network-failure paths passed; allowlisted prompts excluded principal and IP.
- Actual Ollama inference, Docker image build, Compose services, PostgreSQL runtime, and AWS deployment were not executed here.
- GitHub Actions includes PostgreSQL tests and Docker build; it has not run on GitHub yet.
- Two dependency deprecation warnings occurred in the Starlette test client. They did not affect the test results.
- No browser interaction or visual regression testing was performed.
- These tests establish implementation behavior, not real-world detection accuracy.
