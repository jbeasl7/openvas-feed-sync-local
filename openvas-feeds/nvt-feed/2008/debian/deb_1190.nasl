# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57484");
  script_cve_id("CVE-2006-4305");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1190-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1190-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1190-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1190");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'maxdb-7.5.00' package(s) announced via the DSA-1190-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Oliver Karow discovered that the WebDBM frontend of the MaxDB database performs insufficient sanitising of requests passed to it, which might lead to the execution of arbitrary code.

For the stable distribution (sarge) this problem has been fixed in version 7.5.00.24-4.

For the unstable distribution (sid) this problem will be fixed soon.

We recommend that you upgrade your maxdb-7.5.00 package.");

  script_tag(name:"affected", value:"'maxdb-7.5.00' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"libsqldbc7.5.00", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqldbc7.5.00-dev", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlod7.5.00", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsqlod7.5.00-dev", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"maxdb-dbanalyzer", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"maxdb-dbmcli", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"maxdb-loadercli", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"maxdb-lserver", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"maxdb-server", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"maxdb-server-7.5.00", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"maxdb-server-dbg-7.5.00", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"maxdb-sqlcli", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"maxdb-webtools", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-maxdb", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-maxdb-loader", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.3-maxdb", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.3-maxdb-loader", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-maxdb", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.4-maxdb-loader", ver:"7.5.00.24-4", rls:"DEB3.1"))) {
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
