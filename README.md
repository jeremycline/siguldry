# Siguldry

A set of tools and services designed to replace [Sigul](https://pagure.io/sigul).

Currently, this only implements a bridging service between pesign-client and a
Sigul server. In the future, it will have an implementation of the Sigul client,
as well as the bridge and server. Sigul relies on python-nss among other things,
which is unmaintained upstream and is going to be removed from Fedora.