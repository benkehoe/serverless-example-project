# Tests

The testing philosophy is that business logic that can be encapsulated in a largely API-call-free manner can and should be unit tested, but everything that requires significant service integration (e.g., calls APIs) should be tested only as a deployed system.

I'm against local mocking of services, for two reasons:
* There will always be drift between the local implementation and the extant service behavior.
* Relying on a local mock constrains you from using new features from the service until the inevitably-lagging local mock implements them as well, and your development tooling should never determine your production architecture.

## Unit testing

## Integration testing