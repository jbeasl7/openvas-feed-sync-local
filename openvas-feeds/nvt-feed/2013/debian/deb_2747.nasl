# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702747");
  script_cve_id("CVE-2013-5588", "CVE-2013-5589");
  script_tag(name:"creation_date", value:"2013-08-30 22:00:00 +0000 (Fri, 30 Aug 2013)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2747-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2747-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/DSA-2747-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2747");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cacti' package(s) announced via the DSA-2747-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were discovered in Cacti, a web interface for graphing of monitoring systems:

CVE-2013-5588

install/index.php and cacti/host.php suffered from Cross-Site Scripting vulnerabilities.

CVE-2013-5589

cacti/host.php contained an SQL injection vulnerability, allowing an attacker to execute SQL code on the database used by Cacti.

For the oldstable distribution (squeeze), these problems have been fixed in version 0.8.7g-1+squeeze3.

For the stable distribution (wheezy), these problems have been fixed in version 0.8.8a+dfsg-5+deb7u2.

For the unstable distribution (sid), these problems have been fixed in version 0.8.8b+dfsg-3.

We recommend that you upgrade your cacti packages.");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian 6, Debian 7.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.7g-1+squeeze3", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.8a+dfsg-5+deb7u2", rls:"DEB7"))) {
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
