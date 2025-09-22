# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63063");
  script_cve_id("CVE-2008-2380", "CVE-2008-2667");
  script_tag(name:"creation_date", value:"2008-12-29 21:42:24 +0000 (Mon, 29 Dec 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1688-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1688-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1688-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1688");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'courier-authlib' package(s) announced via the DSA-1688-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two SQL injection vulnerabilities have been found in courier-authlib, the courier authentication library. The MySQL database interface used insufficient escaping mechanisms when constructing SQL statements, leading to SQL injection vulnerabilities if certain charsets are used (CVE-2008-2380). A similar issue affects the PostgreSQL database interface (CVE-2008-2667).

For the stable distribution (etch), these problems have been fixed in version 0.58-4+etch2.

For the testing distribution (lenny) and the unstable distribution (sid), these problems have been fixed in version 0.61.0-1+lenny1.

We recommend that you upgrade your courier-authlib packages.");

  script_tag(name:"affected", value:"'courier-authlib' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"courier-authdaemon", ver:"0.58-4+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-authlib", ver:"0.58-4+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-dev", ver:"0.58-4+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-ldap", ver:"0.58-4+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-mysql", ver:"0.58-4+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-pipe", ver:"0.58-4+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-postgresql", ver:"0.58-4+etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"courier-authlib-userdb", ver:"0.58-4+etch2", rls:"DEB4"))) {
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
