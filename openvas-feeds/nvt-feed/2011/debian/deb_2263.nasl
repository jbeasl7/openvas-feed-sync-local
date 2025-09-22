# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69969");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2263-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2263-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2263-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2263");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'movabletype-opensource' package(s) announced via the DSA-2263-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Movable Type, a weblog publishing system, contains several security vulnerabilities:

A remote attacker could execute arbitrary code in a logged-in users' web browser.

A remote attacker could read or modify the contents in the system under certain circumstances.

For the oldstable distribution (lenny), these problems have been fixed in version 4.2.3-1+lenny3.

For the stable distribution (squeeze), these problems have been fixed in version 4.3.5+dfsg-2+squeeze2.

For the testing distribution (wheezy) and for the unstable distribution (sid), these problems have been fixed in version 4.3.6.1+dfsg-1.

We recommend that you upgrade your movabletype-opensource packages.");

  script_tag(name:"affected", value:"'movabletype-opensource' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"movabletype-opensource", ver:"4.2.3-1+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"movabletype-plugin-core", ver:"4.2.3-1+lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
