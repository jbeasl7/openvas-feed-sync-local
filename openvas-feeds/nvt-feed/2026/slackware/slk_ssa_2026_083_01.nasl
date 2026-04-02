# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2026.083.01");
  script_cve_id("CVE-2025-59375", "CVE-2026-4684", "CVE-2026-4685", "CVE-2026-4686", "CVE-2026-4687", "CVE-2026-4688", "CVE-2026-4689", "CVE-2026-4690", "CVE-2026-4691", "CVE-2026-4692", "CVE-2026-4693", "CVE-2026-4694", "CVE-2026-4695", "CVE-2026-4696", "CVE-2026-4697", "CVE-2026-4698", "CVE-2026-4699", "CVE-2026-4700", "CVE-2026-4701", "CVE-2026-4702", "CVE-2026-4704", "CVE-2026-4705", "CVE-2026-4706", "CVE-2026-4707", "CVE-2026-4708", "CVE-2026-4709", "CVE-2026-4710", "CVE-2026-4711", "CVE-2026-4712", "CVE-2026-4713", "CVE-2026-4714", "CVE-2026-4715", "CVE-2026-4716", "CVE-2026-4717", "CVE-2026-4718", "CVE-2026-4719", "CVE-2026-4720", "CVE-2026-4721");
  script_tag(name:"creation_date", value:"2026-03-25 04:40:43 +0000 (Wed, 25 Mar 2026)");
  script_version("2026-03-26T06:06:30+0000");
  script_tag(name:"last_modification", value:"2026-03-26 06:06:30 +0000 (Thu, 26 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-25 15:29:55 +0000 (Wed, 25 Mar 2026)");

  script_name("Slackware: Security Advisory (SSA:2026-083-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2026-083-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2026&m=slackware-security.507780");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-59375");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4684");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4685");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4686");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4687");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4688");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4689");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4690");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4691");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4692");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4693");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4694");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4695");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4696");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4697");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4698");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4699");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4700");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4701");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4702");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4704");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4705");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4706");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4707");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4708");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4709");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4710");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4711");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4712");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4713");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4714");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4715");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4716");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4717");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4718");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4719");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4720");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-4721");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/140.9.0/releasenotes/");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/advisories/mfsa2026-22/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-firefox' package(s) announced via the SSA:2026-083-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mozilla-firefox packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/mozilla-firefox-140.9.0esr-i686-1_slack15.0.txz: Upgraded.
 This update contains security fixes and improvements.
 For more information, see:
 [links moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Slackware 15.0, Slackware current.");

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

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.9.0esr-i686-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.9.0esr-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.9.0esr-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.9.0esr-x86_64-1", rls:"SLKcurrent"))) {
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
