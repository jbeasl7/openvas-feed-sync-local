# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55886");
  script_cve_id("CVE-2005-0870", "CVE-2005-2600", "CVE-2005-3347", "CVE-2005-3348");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-899-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-899-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-899-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-899");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'egroupware' package(s) announced via the DSA-899-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in egroupware, a web-based groupware suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-0870

Maksymilian Arciemowicz discovered several cross site scripting problems in phpsysinfo, which are also present in the imported version in egroupware and of which not all were fixed in DSA 724.

CVE-2005-2600

Alexander Heidenreich discovered a cross-site scripting problem in the tree view of FUD Forum Bulletin Board Software, which is also present in egroupware and allows remote attackers to read private posts via a modified mid parameter.

CVE-2005-3347

Christopher Kunz discovered that local variables get overwritten unconditionally in phpsysinfo, which are also present in egroupware, and are trusted later, which could lead to the inclusion of arbitrary files.

CVE-2005-3348

Christopher Kunz discovered that user-supplied input is used unsanitised in phpsysinfo and imported in egroupware, causing a HTTP Response splitting problem.

The old stable distribution (woody) does not contain egroupware packages.

For the stable distribution (sarge) this problem has been fixed in version 1.0.0.007-2.dfsg-2sarge4.

For the unstable distribution (sid) this problem has been fixed in version 1.0.0.009.dfsg-3-3.

We recommend that you upgrade your egroupware packages.");

  script_tag(name:"affected", value:"'egroupware' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"egroupware", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-addressbook", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-bookmarks", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-calendar", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-comic", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-core", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-developer-tools", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-email", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-emailadmin", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-etemplate", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-felamimail", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-filemanager", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-forum", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-ftp", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-fudforum", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-headlines", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-infolog", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-jinn", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-ldap", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-manual", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-messenger", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-news-admin", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-phpbrain", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-phpldapadmin", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-phpsysinfo", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-polls", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-projects", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-registration", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-sitemgr", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-stocks", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-tts", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"egroupware-wiki", ver:"1.0.0.007-2.dfsg-2sarge4", rls:"DEB3.1"))) {
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
