# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2026.014.02");
  script_cve_id("CVE-2025-14327", "CVE-2026-0877", "CVE-2026-0878", "CVE-2026-0879", "CVE-2026-0880", "CVE-2026-0882", "CVE-2026-0883", "CVE-2026-0884", "CVE-2026-0885", "CVE-2026-0886", "CVE-2026-0887", "CVE-2026-0890", "CVE-2026-0891");
  script_tag(name:"creation_date", value:"2026-01-15 04:19:15 +0000 (Thu, 15 Jan 2026)");
  script_version("2026-01-15T05:47:46+0000");
  script_tag(name:"last_modification", value:"2026-01-15 05:47:46 +0000 (Thu, 15 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-10 20:29:43 +0000 (Wed, 10 Dec 2025)");

  script_name("Slackware: Security Advisory (SSA:2026-014-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2026-014-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2026&m=slackware-security.415023");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-14327");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0877");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0878");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0879");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0880");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0882");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0883");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0884");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0885");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0886");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0887");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0890");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-0891");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/140.7.0/releasenotes/");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/advisories/mfsa2026-03/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-firefox' package(s) announced via the SSA:2026-014-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mozilla-firefox packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/mozilla-firefox-140.7.0esr-i686-1_slack15.0.txz: Upgraded.
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.7.0esr-i686-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.7.0esr-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.7.0esr-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.7.0esr-x86_64-1", rls:"SLKcurrent"))) {
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
