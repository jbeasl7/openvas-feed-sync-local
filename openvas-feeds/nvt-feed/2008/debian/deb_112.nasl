# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53392");
  script_cve_id("CVE-2002-0239");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 112-1 (hanterm)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20112-1");
  script_tag(name:"insight", value:"A set of buffer overflow problems have been found in hanterm, a Hangul
terminal for X11 derived from xterm, that will read and display Korean
characters in its terminal window.  The font handling code in hanterm
uses hard limited string variables but didn't check for boundaries.

This problem can be exploited by a malicious user to gain access to
the utmp group which is able to write the wtmp and utmp files.  These
files record login and logout activities.

This problem has been fixed in version 3.3.1p17-5.2 for the stable
Debian distribution.  A fixed package for the current testing/unstable
distribution is not yet available but will have a version number
higher than 3.3.1p18-6.1.");

  script_tag(name:"solution", value:"We recommend that you upgrade your hanterm packages immediately if you");
  script_tag(name:"summary", value:"The remote host is missing an update to hanterm
announced via advisory DSA 112-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"hanterm", ver:"3.3.1p17-5.2", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
