# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2018.229.01");
  script_cve_id("CVE-2016-1549", "CVE-2018-12327");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2025-01-14T05:37:02+0000");
  script_tag(name:"last_modification", value:"2025-01-14 05:37:02 +0000 (Tue, 14 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-10 16:57:49 +0000 (Fri, 10 Aug 2018)");

  script_name("Slackware: Security Advisory (SSA:2018-229-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.0|14\.1|14\.2|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2018-229-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2018&m=slackware-security.505174");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/SecurityNotice#August_2018_ntp_4_2_8p12_NTP_Rel");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SSA:2018-229-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New ntp packages are available for Slackware 14.0, 14.1, 14.2, and -current to
fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/ntp-4.2.8p12-i586-1_slack14.2.txz: Upgraded.
 This release improves on one security fix in ntpd:
 LOW/MEDIUM: Sec 3012: Sybil vulnerability: ephemeral association attack
 While fixed in ntp-4.2.8p7 and with significant additional protections for
 this issue in 4.2.8p11, ntp-4.2.8p12 includes a fix for an edge case in
 the new noepeer support. Originally reported by Matt Van Gundy of Cisco.
 Edge-case hole reported by Martin Burnicki of Meinberg.
 And fixes another security issue in ntpq and ntpdc:
 LOW: Sec 3505: The openhost() function used during command-line hostname
 processing by ntpq and ntpdc can write beyond its buffer limit, which
 could allow an attacker to achieve code execution or escalate to higher
 privileges via a long string as the argument for an IPv4 or IPv6
 command-line parameter. NOTE: It is unclear whether there are any common
 situations in which ntpq or ntpdc is used with a command line from an
 untrusted source. Reported by Fakhri Zulkifli.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'ntp' package(s) on Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware current.");

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

if(release == "SLK14.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"ntp", ver:"4.2.8p12-i486-1_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ntp", ver:"4.2.8p12-x86_64-1_slack14.0", rls:"SLK14.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.1") {

  if(!isnull(res = isslkpkgvuln(pkg:"ntp", ver:"4.2.8p12-i486-1_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ntp", ver:"4.2.8p12-x86_64-1_slack14.1", rls:"SLK14.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLK14.2") {

  if(!isnull(res = isslkpkgvuln(pkg:"ntp", ver:"4.2.8p12-i586-1_slack14.2", rls:"SLK14.2"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ntp", ver:"4.2.8p12-x86_64-1_slack14.2", rls:"SLK14.2"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"ntp", ver:"4.2.8p12-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ntp", ver:"4.2.8p12-x86_64-1", rls:"SLKcurrent"))) {
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
