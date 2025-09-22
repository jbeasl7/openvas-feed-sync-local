# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53119");
  script_cve_id("CVE-2004-0016", "CVE-2004-0017");
  script_tag(name:"creation_date", value:"2008-01-17 21:41:51 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-419)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-419");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/DSA-419");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-419");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpgroupware' package(s) announced via the DSA-419 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The authors of phpgroupware, a web based groupware system written in PHP, discovered several vulnerabilities. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2004-0016

In the 'calendar' module, 'save extension' was not enforced for holiday files. As a result, server-side php scripts may be placed in directories that then could be accessed remotely and cause the webserver to execute those. This was resolved by enforcing the extension '.txt' for holiday files.

CAN-2004-0017

Some SQL injection problems (non-escaping of values used in SQL strings) the 'calendar' and 'infolog' modules.

Additionally, the Debian maintainer adjusted the permissions on world writable directories that were accidentally created by former postinst during the installation.

For the stable distribution (woody) this problem has been fixed in version 0.9.14-0.RC3.2.woody3.

For the unstable distribution (sid) this problem has been fixed in version 0.9.14.007-4.

We recommend that you upgrade your phpgroupware, phpgroupware-calendar and phpgroupware-infolog packages.");

  script_tag(name:"affected", value:"'phpgroupware' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-addressbook", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-admin", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-api", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-api-doc", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-bookkeeping", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-bookmarks", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-brewer", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-calendar", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-chat", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-chora", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-comic", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-core", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-core-doc", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-developer-tools", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-dj", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-eldaptir", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-email", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-filemanager", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-forum", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-ftp", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-headlines", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-hr", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-img", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-infolog", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-inv", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-manual", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-messenger", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-napster", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-news-admin", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-nntp", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-notes", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phonelog", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpsysinfo", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-phpwebhosting", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-polls", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-preferences", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-projects", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-registration", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-setup", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-skel", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-soap", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-stocks", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-todo", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-tts", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-wap", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-weather", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"phpgroupware-xmlrpc", ver:"0.9.14-0.RC3.2.woody3", rls:"DEB3.0"))) {
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
