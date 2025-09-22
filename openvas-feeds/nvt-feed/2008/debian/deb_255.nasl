# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53330");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0108");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Debian Security Advisory DSA 255-1 (tcpdump)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20255-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6974");
  script_tag(name:"insight", value:"Andrew Griffiths and iDEFENSE Labs discovered a problem in tcpdump, a
powerful tool for network monitoring and data acquisition.  An
attacker is able to send a specially crafted network packet which
causes tcpdump to enter an infinite loop.

In addition to the above problem the tcpdump developers discovered a
potential infinite loop when parsing malformed BGP packets.  They also
discovered a buffer overflow that can be exploited with certain
malformed NFS packets.

For the stable distribution (woody) these problems have been
fixed in version 3.6.2-2.3.

For the old stable distribution (potato) does not seem to be affected
by this problem.

For the unstable distribution (sid) these problems have been fixed in
version 3.7.1-1.2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your tcpdump packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to tcpdump
announced via advisory DSA 255-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"tcpdump", ver:"3.6.2-2.3", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
