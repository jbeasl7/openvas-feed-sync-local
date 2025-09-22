# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63888");
  script_cve_id("CVE-2009-0664");
  script_tag(name:"creation_date", value:"2009-04-28 18:40:12 +0000 (Tue, 28 Apr 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1778-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-1778-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1778-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1778");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mahara' package(s) announced via the DSA-1778-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that mahara, an electronic portfolio, weblog, and resume builder, is prone to cross-site scripting (XSS) attacks because of missing input sanitization of the introduction text field in user profiles and any text field in a user view.

The oldstable distribution (etch) does not contain mahara.

For the stable distribution (lenny), this problem has been fixed in version 1.0.4-4+lenny2.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.1.3-1.

We recommend that you upgrade your mahara packages.");

  script_tag(name:"affected", value:"'mahara' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mahara", ver:"1.0.4-4+lenny2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mahara-apache2", ver:"1.0.4-4+lenny2", rls:"DEB5"))) {
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
