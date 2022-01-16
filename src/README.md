# Lambda function code layout

There's one source directory, and therefore one zip file, for all functions.
The size of the code is not huge, so the impact on cold start is small.
It reduces uploads.

This means each function has the same `CodeUri` property but a different `Handler` (see below).

Function handlers deal with transforming the input from its API-specific format into an internal representation, calling business logic functions from a common library, and transforming the output to the API-specific format as necessary.

The common library is intended to be unit testable; function handler code is tested purely through integration tests.

## Common code and business logic

Common code and the bulk of business logic is a shared library here.
I prefer to name the library after the service, so it has an unambiguous name no matter the context.
A valid alternative is to always name it something like `common`, because it should only be used from functions within the service, but I avoid this because copying and pasting code between services could cause confusion.

## Function handlers

Each Lambda function gets its own handler file at the top level.
They all have the same handler function name, `handler`.