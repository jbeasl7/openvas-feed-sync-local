# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55885");
  script_cve_id("CVE-2005-0870", "CVE-2005-3347", "CVE-2005-3348");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-898-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-898-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-898-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-898");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpgroupware' package(s) announced via the DSA-898-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in phpsysinfo, a PHP based host information application that is included in phpgroupware. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-0870

Maksymilian Arciemowicz discovered several cross site scripting problems, of which not all were fixed in DSA 724.

CVE-2005-3347

Christopher Kunz discovered that local variables get overwritten unconditionally and are trusted later, which could lead to the inclusion of arbitrary files.

CVE-2005-3348

Christopher Kunz discovered that user-supplied input is used unsanitised, causing a HTTP Response splitting problem.

For the old stable distribution (woody) these problems have been fixed in version 0.9.14-0.RC3.2.woody5.

For the stable distribution (sarge) these problems have been fixed in version 0.9.16.005-3.sarge4.

For the unstable distribution (sid) these problems have been fixed in version 0.9.16.008-2.

We recommend that you upgrade your phpgroupware packages.");

  script_tag(name:"affected", value:"'phpgroupware' package(s) on Debian 3.0, Debian 3.1.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-addressbook", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-admin", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-api", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-api-doc", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-bookkeeping", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-bookmarks", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-brewer", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-calendar", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-chat", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-chora", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-comic", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-core", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-core-doc", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-developer-tools", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-dj", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-eldaptir", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-email", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-filemanager", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-forum", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-ftp", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-headlines", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-hr", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-img", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-infolog", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-inv", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-manual", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-messenger", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-napster", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-news-admin", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-nntp", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-notes", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phonelog", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpsysinfo", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpwebhosting", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-polls", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-preferences", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-projects", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-registration", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-setup", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-skel", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-soap", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-stocks", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-todo", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-tts", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-wap", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-weather", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-xmlrpc", ver:"0.9.14-0.RC3.2.woody5", rls:"DEB3.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-addressbook", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-admin", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-bookmarks", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-calendar", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-chat", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-comic", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-core", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-developer-tools", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-dj", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-eldaptir", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-email", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-etemplate", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-felamimail", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-filemanager", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-folders", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-forum", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-ftp", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-fudforum", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-headlines", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-hr", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-img", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-infolog", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-manual", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-messenger", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-news-admin", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-nntp", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-notes", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phonelog", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpbrain", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpgwapi", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpsysinfo", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-polls", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-preferences", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-projects", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-qmailldap", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-registration", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-setup", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-sitemgr", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-skel", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-soap", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-stocks", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-todo", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-tts", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-wiki", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-xmlrpc", ver:"0.9.16.005-3.sarge4", rls:"DEB3.1"))) {
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
