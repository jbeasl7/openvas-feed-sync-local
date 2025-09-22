# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53412");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2002-0872", "CVE-2002-0873");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 152-1 (l2tpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20152-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5451");
  script_tag(name:"insight", value:"Current versions of l2tpd, a layer 2 tunneling client/server program,
forgot to initialize the random generator which made it vulnerable
since all generated random number were 100% guessable.  When dealing
with the size of the value in an attribute value pair, too many bytes
were able to be copied, which could lead into the vendor field being
overwritten.

These problems have been fixed in version 0.67-1.1 for the current
stable distribution (woody) and in version 0.68-1 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected, since it doesn't contain the l2tpd package.");

  script_tag(name:"solution", value:"We recommend that you upgrade your l2tpd packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to l2tpd
announced via advisory DSA 152-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"l2tpd", ver:"0.67-1.1", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
