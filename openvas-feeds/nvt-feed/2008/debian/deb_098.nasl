# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53836");
  script_cve_id("CVE-2001-0927", "CVE-2001-0928");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 098-1 (libgtop)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20098-1");
  script_tag(name:"insight", value:"Two different problems were found in libgtop-daemon:

  * The laboratory intexxia found a format string problem in the logging
code from libgtop_daemon. There were two logging functions which are
called when authorizing a client which could be exploited by a remote
user.

  * Flavio Veloso found a buffer overflow in the function that authorizes
clients

Since libgtop_daemon runs as user nobody both bugs could be used
to gain access as the nobody user to a system running libgtop_daemon.

Both problems have been fixed in version 1.0.6-1.1 and we recommend
you upgrade your libgtop-daemon package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to libgtop
announced via advisory DSA 098-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libgtop-daemon", ver:"1.0.6-1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgtop-dev", ver:"1.0.6-1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgtop1", ver:"1.0.6-1.1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
