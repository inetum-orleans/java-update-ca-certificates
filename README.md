Java Update Ca Certificates
===========================

OpenJDK doesn't use CA Certificates installed on the system, but use a custom Root CA Certificate store.

This may cause error if you rely on custom CA certificate to access some HTTPS urls or if you are behind a SSL
Proxy.

This tool will install custom CA certificates in JVM Root CA Certificate Keystore.

Install and run
---------------

- Use maven wrapper to build the project

```
mvnw package
```

- Execute the jar from the java environment you want to add CA certificate.

```
# This will intercept untrusted certificates when connecting to google.com
java -jar target/update-ca-certificates.jar
```

Usage
-----

```
Usage: <main class> [-g=<glob>] [-h=<host>] [-i=<index>] [-p=<port>]
                    [-t=<truststore>] [-d=<directory>]... [-f=<file>]...
  -d, --directory=<directory>
                        Directory containing .crt files to update.
  -f, --file=<file>     File containing certificate file (PEM).
  -g, --glob=<glob>     Glob filter of certificate files to load.
  -h, --host=<host>     Host to check. This will intercept SSL certificates chain
                          returned by this host. If chain is not trusted, it will
                          add the last certificate in chain to trusted store, or the
                          one specified by index option.(default: google.com)
  -i, --index=<index>   Index of the certificate to add. (default: Last certificate
                          index in certificate chain)
  -p, --port=<port>     TCP port of the host to check. (default: 443)
  -t, --truststore=<truststore>
                        Truststore file to used.
```



Build
-----

- Run `mvn package`