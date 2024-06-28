# forward-auth-oidc-claims
Implementation of a Forward Auth provider for Traefik that parses custom claims into headers.

Note that the values from the claims will be JSON-encoded.
This is because there are many different types of claim values,
and in particular strings can be non-ASCII,
so for uniformity they will be JSON-encoded.