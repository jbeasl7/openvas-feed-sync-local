# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58595");
  script_cve_id("CVE-2007-3189", "CVE-2007-3190", "CVE-2007-3191", "CVE-2007-3192");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_name("Debian: Security Advisory (DSA-1374-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1374-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1374-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1374");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jffnms' package(s) announced via the DSA-1374-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in jffnms, a web-based Network Management System for IP networks. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3189

Cross-site scripting (XSS) vulnerability in auth.php, which allows a remote attacker to inject arbitrary web script or HTML via the user parameter.

CVE-2007-3190

Multiple SQL injection vulnerabilities in auth.php, which allow remote attackers to execute arbitrary SQL commands via the user and pass parameters.

CVE-2007-3192

Direct requests to URLs make it possible for remote attackers to access configuration information, bypassing login restrictions.

For the stable distribution (etch), these problems have been fixed in version 0.8.3dfsg.1-2.1etch1.

For the unstable distribution (sid), these problems have been fixed in version 0.8.3dfsg.1-4.

We recommend that you upgrade your jffnms package.");

  script_tag(name:"affected", value:"'jffnms' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"jffnms", ver:"0.8.3dfsg.1-2.1etch1", rls:"DEB4"))) {
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
