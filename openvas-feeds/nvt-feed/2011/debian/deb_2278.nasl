# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69987");
  script_cve_id("CVE-2010-3077", "CVE-2010-3694");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2278-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2278-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2278-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2278");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'horde3' package(s) announced via the DSA-2278-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that horde3, the horde web application framework, is prone to a cross-site scripting attack and a cross-site request forgery.

For the oldstable distribution (lenny), these problems have been fixed in version 3.2.2+debian0-2+lenny3.

For the stable distribution (squeeze), these problems have been fixed in version 3.3.8+debian0-2, which was already included in the squeeze release.

For the testing distribution (wheezy) and the unstable distribution (sid), these problems have been fixed in version 3.3.8+debian0-2.

We recommend that you upgrade your horde3 packages.");

  script_tag(name:"affected", value:"'horde3' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"horde3", ver:"3.2.2+debian0-2+lenny3", rls:"DEB5"))) {
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
