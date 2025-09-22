# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53334");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
  script_cve_id("CVE-2003-0146");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 263-1 (netpbm-free)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20263-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6979");
  script_tag(name:"insight", value:"Al Viro and Alan Cox discovered several maths overflow errors in
NetPBM, a set of graphics conversion tools.  These programs are not
installed setuid root but are often installed to prepare data for
processing.  These vulnerabilities may allow remote attackers to cause
a denial of service or execute arbitrary code.

For the stable distribution (woody) this problem has been
fixed in version 9.20-8.2.

The old stable distribution (potato) does not seem to be affected
by this problem.

For the unstable distribution (sid) this problem has been
fixed in version 9.20-9.");

  script_tag(name:"solution", value:"We recommend that you upgrade your netpbm package.");
  script_tag(name:"summary", value:"The remote host is missing an update to netpbm-free
announced via advisory DSA 263-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libnetpbm9", ver:"9.20-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libnetpbm9-dev", ver:"9.20-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"netpbm", ver:"9.20-8.2", rls:"DEB3.0")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
