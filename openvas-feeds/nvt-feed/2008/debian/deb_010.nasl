# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53861");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Debian Security Advisory DSA 010-1 (gnupg)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20010-1");
  script_tag(name:"insight", value:"Two bugs in GnuPG have recently been found:

1. false positives when verifying detached signatures

  - -----------------------------------------------------

There is a problem in the way gpg checks detached signatures which
can lead to false positives. Detached signature can be verified
with a command like this:

gpg --verify detached.sig < mydata

If someone replaced detached.sig with a signed text (ie not a
detached signature) and then modified mydata gpg would still
report a successfully verified signature.

To fix the way the --verify option works has been changes: it now
needs two options when verifying detached signatures: both the file
with the detached signature, and the file with the data to be
verified. Please note that this makes it incompatible with older
versions!

2. secret keys are silently imported

  - ------------------------------------

Florian Weimer discovered that gpg would import secret keys from
key-servers. Since gpg considers public keys corresponding to
known secret keys to be ultimately trusted an attacked can use this
circumvent the web of trust.

To fix this a new option was added to tell gpg it is allowed
to import secret keys: --allow-key-import.


Both these fixes are in version 1.0.4-1.1 and we recommend that you
upgrade your gnupg package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to gnupg
announced via advisory DSA 010-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"gnupg", ver:"1.0.4-1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
