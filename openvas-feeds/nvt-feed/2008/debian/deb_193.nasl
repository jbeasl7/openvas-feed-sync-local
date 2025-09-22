# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53439");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-1247");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Debian Security Advisory DSA 193-1 (kdenetwork)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20193-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6157");
  script_tag(name:"insight", value:"iDEFENSE reports a security vulnerability in the klisa package, that
provides a LAN information service similar to Network Neighbourhood,
which was discovered by Texonet.  It is possible for a local attacker
to exploit a buffer overflow condition in resLISa, a restricted
version of KLISa.  The vulnerability exists in the parsing of the
LOGNAME environment variable, an overly long value will overwrite the
instruction pointer thereby allowing an attacker to seize control of
the executable.

This problem has been fixed in version 2.2.2-14.2 the current stable
distribution (woody) and in version 2.2.2-14.3 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since it doesn't contain a kdenetwork package");

  script_tag(name:"solution", value:"We recommend that you upgrade your klisa package immediately.");
  script_tag(name:"summary", value:"The remote host is missing an update to kdenetwork
announced via advisory DSA 193-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"klisa", ver:"2.2.2-14.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
