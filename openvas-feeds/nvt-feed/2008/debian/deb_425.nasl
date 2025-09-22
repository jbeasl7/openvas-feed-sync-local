# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53126");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0989", "CVE-2003-1029", "CVE-2004-0055", "CVE-2004-0057");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 425-1 (tcpdump)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20425-1");
  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in tcpdump, a tool for
inspecting network traffic.  If a vulnerable version of tcpdump
attempted to examine a maliciously constructed packet, a number of
buffer overflows could be exploited to crash tcpdump, or potentially
execute arbitrary code with the privileges of the tcpdump process.

CVE-2003-1029 - infinite loop and memory consumption in processing
L2TP packets

CVE-2003-0989, CVE-2004-0057 - infinite loops in processing ISAKMP
packets.

CVE-2004-0055 - segmentation fault caused by a RADIUS attribute with a
large length value

For the current stable distribution (woody) these problems have been
fixed in version 3.6.2-2.7.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you update your tcpdump package.");
  script_tag(name:"summary", value:"The remote host is missing an update to tcpdump
announced via advisory DSA 425-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"tcpdump", ver:"3.6.2-2.7", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
