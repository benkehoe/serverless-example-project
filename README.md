# Example serverless project

The purpose of this project is to demonstrate various recommended practices.

This project is currently under construction.

# Guiding principles

## Less is more, SBOM-wise

* Prefer AWS-native and AWS-provided mechanisms over third-party tools and libraries.
* Prefer thin solutions over thick solutions; this includes frameworks.

## IAM all the things

Have not added auth to the API yet.

* Use IAM and SigV4 rather than OAuth bearer tokens
* Role and policy provided by the service
* Resource policy