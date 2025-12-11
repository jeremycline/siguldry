#include <rpm/header.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmfiles.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmtag.h>

// Crime ahead; these are not in RPM header files. Beg RPM to expose them once we have a nice
// proof of concept.
rpmRC rpmLeadRead(FD_t fd, char **emsg);
rpmRC rpmLeadWrite(FD_t fd, Header h);
rpmRC rpmReadSignature(FD_t fd, Header * sighp, char ** msg);
int rpmWriteSignature(FD_t fd, Header h);
