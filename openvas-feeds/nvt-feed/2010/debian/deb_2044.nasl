# SPDX-FileCopyrightText: 2010 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67387");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-14 20:09:58 +0200 (Fri, 14 May 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 2044-1 (mplayer)");
  script_cve_id("CVE-2010-2062");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202044-1");
  script_tag(name:"insight", value:"tixxDZ (DZCORE labs) discovered a vulnerability in the mplayer movie
player.  Missing data validation in mplayer's real data transport (RDT)
implementation enable an integer underflow and consequently an unbounded
buffer operation.  A maliciously crafted stream could thus enable an
attacker to execute arbitrary code.

No Common Vulnerabilities and Exposures project identifier is available for
this issue.

For the stable distribution (lenny), this problem has been fixed in version
1.0~rc2-17+lenny3.2.");

  script_tag(name:"solution", value:"We recommend that you upgrade your mplayer packages.");
  script_tag(name:"summary", value:"The remote host is missing an update to mplayer
announced via advisory DSA 2044-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"mplayer-doc", ver:"1.0~rc2-17+lenny3.2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mplayer", ver:"1.0~rc2-17+lenny3.2", rls:"DEB5")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"mplayer-dbg", ver:"1.0~rc2-17+lenny3.2", rls:"DEB5")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}