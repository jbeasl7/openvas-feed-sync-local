# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67035");
  script_cve_id("CVE-2010-3313", "CVE-2010-3314");
  script_tag(name:"creation_date", value:"2010-03-16 16:25:39 +0000 (Tue, 16 Mar 2010)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2013-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2013-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/DSA-2013-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2013");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'egroupware' package(s) announced via the DSA-2013-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nahuel Grisolia discovered two vulnerabilities in Egroupware, a web-based groupware suite: Missing input sanitising in the spellchecker integration may lead to the execution of arbitrary commands and a cross-site scripting vulnerability was discovered in the login page.

For the stable distribution (lenny), these problems have been fixed in version 1.4.004-2.dfsg-4.2.

The upcoming stable distribution (squeeze), no longer contains egroupware packages.

We recommend that you upgrade your egroupware packages.");

  script_tag(name:"affected", value:"'egroupware' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"egroupware", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-addressbook", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-bookmarks", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-calendar", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-core", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-developer-tools", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-emailadmin", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-etemplate", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-felamimail", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-filemanager", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-infolog", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-manual", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-mydms", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-news-admin", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-phpbrain", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-phpsysinfo", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-polls", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-projectmanager", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-registration", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-resources", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-sambaadmin", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-sitemgr", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-timesheet", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-tracker", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-wiki", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5"))) {
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
