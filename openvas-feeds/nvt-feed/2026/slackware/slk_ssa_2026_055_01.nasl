# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2026.055.01");
  script_cve_id("CVE-2026-2757", "CVE-2026-2758", "CVE-2026-2759", "CVE-2026-2760", "CVE-2026-2761", "CVE-2026-2762", "CVE-2026-2763", "CVE-2026-2764", "CVE-2026-2765", "CVE-2026-2766", "CVE-2026-2767", "CVE-2026-2768", "CVE-2026-2769", "CVE-2026-2770", "CVE-2026-2771", "CVE-2026-2772", "CVE-2026-2773", "CVE-2026-2774", "CVE-2026-2775", "CVE-2026-2776", "CVE-2026-2777", "CVE-2026-2778", "CVE-2026-2779", "CVE-2026-2780", "CVE-2026-2781", "CVE-2026-2782", "CVE-2026-2783", "CVE-2026-2784", "CVE-2026-2785", "CVE-2026-2786", "CVE-2026-2787", "CVE-2026-2788", "CVE-2026-2789", "CVE-2026-2790", "CVE-2026-2791", "CVE-2026-2792", "CVE-2026-2793");
  script_tag(name:"creation_date", value:"2026-02-25 04:38:04 +0000 (Wed, 25 Feb 2026)");
  script_version("2026-02-26T05:57:26+0000");
  script_tag(name:"last_modification", value:"2026-02-26 05:57:26 +0000 (Thu, 26 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-25 16:02:24 +0000 (Wed, 25 Feb 2026)");

  script_name("Slackware: Security Advisory (SSA:2026-055-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2026-055-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2026&m=slackware-security.503920");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2757");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2758");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2759");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2760");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2761");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2762");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2763");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2764");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2765");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2766");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2767");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2768");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2769");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2770");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2771");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2772");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2773");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2774");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2775");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2776");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2777");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2778");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2779");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2780");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2781");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2782");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2783");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2784");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2785");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2786");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2787");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2788");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2789");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2790");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2791");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2792");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2026-2793");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/140.8.0/releasenotes/");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/advisories/mfsa2026-15/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-firefox' package(s) announced via the SSA:2026-055-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mozilla-firefox packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/mozilla-firefox-140.8.0esr-i686-1_slack15.0.txz: Upgraded.
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.8.0esr-i686-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.8.0esr-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.8.0esr-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"140.8.0esr-x86_64-1", rls:"SLKcurrent"))) {
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
