# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53396");
  script_cve_id("CVE-2002-0092");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 117-1 (cvs)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20117-1");
  script_tag(name:"insight", value:"Kim Nielsen recently found an internal problem with the CVS server and
reported it to the vuln-dev mailing list.  The problem is triggered by
an improperly initialized global variable.  A user exploiting this can
crash the CVS server, which may be accessed through the pserver
service and running under a remote user id.  It is not yet clear if
the remote account can be exposed, through.

This problem has been fixed in version 1.10.7-9 for the stable Debian
distribution and in version newer than 1.11.1p1debian-3 for the
testing and unstable distribution of Debian (not yet uploaded,
though).");

  script_tag(name:"solution", value:"We recommend that you upgrade your CVS package.");
  script_tag(name:"summary", value:"The remote host is missing an update to cvs
announced via advisory DSA 117-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"cvs-doc", ver:"1.10.7-9", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"cvs", ver:"1.10.7-9", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
