# Contributing to Prosze

Thank you for contributing. Prosze is a privacy-focused project, so changes
should preserve the rule that sensitive values stay local and only redacted
content is sent to external commands or services.

## Before you start

- Read the [README](README.md) for the project layout, build commands, and usage.
- Keep `.prosze-map` and other files containing real secrets out of commits.
- Prefer small, focused changes with tests and documentation updates where appropriate.

## Development

The repository contains both a native C++ implementation and a Python package.
Use the existing conventions in the surrounding code and keep behavior aligned
where the two implementations provide the same operation.

For the Python implementation:

```powershell
python -m pip install -e .
python -m unittest discover -s tests -v
```

Run those commands from `new/prosze_ner_updated` for the package installation,
or run the test command from the repository root as shown in the README.

For the native implementation, build with C++17 and run the deterministic test
binary:

```powershell
g++ -std=c++17 -O2 -Wall -Wextra -pedantic prosze\Application.cpp -o .tmp-prosze.exe
g++ -std=c++17 -O2 -Wall -Wextra -pedantic prosze\tests\ApplicationTests.cpp -o .tmp-prosze-tests.exe
.\.tmp-prosze-tests.exe
```

Remove temporary binaries after testing. Do not add generated build output,
local mapping files, model files, or credentials to the repository.

## Pull requests

Please include:

- A clear description of the problem and the change.
- Tests covering new behavior or a note explaining why tests are not needed.
- Any relevant documentation or security-impact notes.
- Confirmation that the change does not expose original sensitive values.

Keep pull requests focused. Reviewers may ask for changes that improve
determinism, cross-platform behavior, error handling, or privacy guarantees.

## Reporting security issues

Do not open a public issue containing secrets, personal data, or an exploitable
vulnerability. Contact the project maintainers privately with reproduction
details and the potential impact.

## License

By contributing, you agree that your contributions are provided under the
[MIT License](LICENSE).
