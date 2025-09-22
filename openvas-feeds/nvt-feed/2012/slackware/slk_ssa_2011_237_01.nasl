# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71962");
  script_cve_id("CVE-2011-1148", "CVE-2011-1938", "CVE-2011-2202", "CVE-2011-2483");
  script_tag(name:"creation_date", value:"2012-09-10 11:16:18 +0000 (Mon, 10 Sep 2012)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2011-237-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(11\.0|12\.0|12\.1|12\.2|13\.0|13\.1|13\.37|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2011-237-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2011&m=slackware-security.575575");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the SSA:2011-237-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New php packages are available for Slackware 11.0, 12.0, 12.1, 12.2, 13.0,
13.1, 13.37, and -current to fix security issues.


Here are the details from the Slackware 13.37 ChangeLog:
+--------------------------+
patches/packages/php-5.3.8-i486-1_slack13.37.txz: Upgraded.
 Security fixes vs. 5.3.6 (5.3.7 was not usable):
 Updated crypt_blowfish to 1.2. (CVE-2011-2483)
 Fixed crash in error_log(). Reported by Mateusz Kocielski
 Fixed buffer overflow on overlog salt in crypt().
 Fixed bug #54939 (File path injection vulnerability in RFC1867
 File upload filename). Reported by Krzysztof Kotowicz. (CVE-2011-2202)
 Fixed stack buffer overflow in socket_connect(). (CVE-2011-1938)
 Fixed bug #54238 (use-after-free in substr_replace()). (CVE-2011-1148)
 For more information, see:
 [links moved to references]
 For those upgrading from PHP 5.2.x, be aware that quite a bit has
 changed, and it will very likely not 'drop in', but PHP 5.2.x is not
 supported by php.net any longer, so there wasn't a lot of choice
 in the matter. We're not able to support a security fork of
 PHP 5.2.x here either, so you'll have to just bite the bullet on
 this. You'll be better off in the long run. :)
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'php' package(s) on Slackware 11.0, Slackware 12.0, Slackware 12.1, Slackware 12.2, Slackware 13.0, Slackware 13.1, Slackware 13.37, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK11.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-i486-1_slack11.0", rls:"SLK11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-i486-1_slack12.0", rls:"SLK12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-i486-1_slack12.1", rls:"SLK12.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK12.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-i486-1_slack12.2", rls:"SLK12.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-i486-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-x86_64-1_slack13.0", rls:"SLK13.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-i486-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-x86_64-1_slack13.1", rls:"SLK13.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK13.37") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-i486-1_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-x86_64-1_slack13.37", rls:"SLK13.37"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-i486-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.3.8-x86_64-1", rls:"SLKcurrent"))) {
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
