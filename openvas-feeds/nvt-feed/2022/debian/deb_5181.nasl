# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705181");
  script_cve_id("CVE-2022-25802");
  script_tag(name:"creation_date", value:"2022-07-15 01:00:08 +0000 (Fri, 15 Jul 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 10:41:11 +0000 (Wed, 20 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-5181-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"Advisory-ID", value:"DSA-5181-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/DSA-5181-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5181");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/request-tracker4");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'request-tracker4' package(s) announced via the DSA-5181-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Request Tracker, an extensible trouble-ticket tracking system.

CVE-2022-25802

It was discovered that Request Tracker is vulnerable to a cross-site scripting (XSS) attack when displaying attachment content with fraudulent content types.

Additionally it was discovered that Request Tracker did not perform full rights checks on accesses to file or image type custom fields, possibly allowing access to these custom fields by users without rights to access to the associated objects, resulting in information disclosure.

For the oldstable distribution (buster), these problems have been fixed in version 4.4.3-2+deb10u2.

For the stable distribution (bullseye), these problems have been fixed in version 4.4.4+dfsg-2+deb11u2.

We recommend that you upgrade your request-tracker4 packages.

For the detailed security status of request-tracker4 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'request-tracker4' package(s) on Debian 10, Debian 11.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.4.3-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.4.3-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.4.3-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.4.3-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.4.3-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.4.3-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-doc-html", ver:"4.4.3-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.4.3-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-standalone", ver:"4.4.3-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker4", ver:"4.4.4+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-apache2", ver:"4.4.4+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-clients", ver:"4.4.4+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-mysql", ver:"4.4.4+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-postgresql", ver:"4.4.4+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-db-sqlite", ver:"4.4.4+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-doc-html", ver:"4.4.4+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-fcgi", ver:"4.4.4+dfsg-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt4-standalone", ver:"4.4.4+dfsg-2+deb11u2", rls:"DEB11"))) {
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
