# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2025.175.02");
  script_cve_id("CVE-2025-6424", "CVE-2025-6425", "CVE-2025-6426", "CVE-2025-6427", "CVE-2025-6428", "CVE-2025-6429", "CVE-2025-6430", "CVE-2025-6431", "CVE-2025-6432", "CVE-2025-6433", "CVE-2025-6434", "CVE-2025-6435", "CVE-2025-6436");
  script_tag(name:"creation_date", value:"2025-06-25 04:17:13 +0000 (Wed, 25 Jun 2025)");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2025-175-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2025-175-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2025&m=slackware-security.418871");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6424");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6425");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6426");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6427");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6428");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6429");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6430");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6431");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6432");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6433");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6434");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6435");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2025-6436");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/140.0/releasenotes/");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/advisories/mfsa2025-51");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-firefox' package(s) announced via the SSA:2025-175-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mozilla-firefox packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/mozilla-firefox-140.0esr-i686-1_slack15.0.txz: Upgraded.
 This update contains security fixes and improvements, and moves to the new
 Firefox 140 ESR branch. See the release notes for details about some of the
 new features.
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.0esr-i686-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.0esr-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.0esr-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.0esr-x86_64-1", rls:"SLKcurrent"))) {
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
