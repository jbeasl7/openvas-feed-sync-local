# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61457");
  script_cve_id("CVE-2008-0599");
  script_tag(name:"creation_date", value:"2012-09-10 23:34:21 +0000 (Mon, 10 Sep 2012)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 13:52:57 +0000 (Fri, 02 Feb 2024)");

  script_name("Slackware: Security Advisory (SSA:2008-128-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(10\.2|11\.0|12\.0|12\.1|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2008-128-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2008&m=slackware-security.488951");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_6.php");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php' package(s) announced via the SSA:2008-128-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New php packages are available for Slackware 10.2, 11.0, 12.0, 12.1,
and -current to fix security issues.

Note that PHP5 is not the default PHP for Slackware 10.2 or 11.0 (those use
PHP4), so if your PHP code is not ready for PHP5, don't upgrade until it is
or you'll (by definition) run into problems.

More details about one of the issues may be found in the Common
Vulnerabilities and Exposures (CVE) database:

 [link moved to references]


Here are the details from the Slackware 12.1 ChangeLog:
+--------------------------+
patches/packages/php-5.2.6-i486-1_slack12.1.tgz:
 Upgraded to php-5.2.6.
 This version of PHP contains many fixes and enhancements. Some of the fixes
 are security related, and the PHP release announcement provides this list:
 * Fixed possible stack buffer overflow in the FastCGI SAPI identified by
 Andrei Nigmatulin.
 * Fixed integer overflow in printf() identified by Maksymilian Aciemowicz.
 * Fixed security issue detailed in CVE-2008-0599 identified by Ryan Permeh.
 * Fixed a safe_mode bypass in cURL identified by Maksymilian Arciemowicz.
 * Properly address incomplete multibyte chars inside escapeshellcmd()
 identified by Stefan Esser.
 * Upgraded bundled PCRE to version 7.6
 When last checked, CVE-2008-0599 was not yet open. However, additional
 information should become available at this URL:
 [link moved to references]
 The list reproduced above, as well as additional information about other
 fixes in PHP 5.2.6 may be found in the PHP release announcement here:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'php' package(s) on Slackware 10.2, Slackware 11.0, Slackware 12.0, Slackware 12.1, Slackware current.");

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

if(release == "SLK10.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.6-i486-1_slack10.2", rls:"SLK10.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK11.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.6-i486-1_slack11.0", rls:"SLK11.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.6-i486-1_slack12.0", rls:"SLK12.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.6-i486-1_slack12.1", rls:"SLK12.1"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"php", ver:"5.2.6-i486-1", rls:"SLKcurrent"))) {
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
