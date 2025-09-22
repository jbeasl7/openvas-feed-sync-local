# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14124.1");
  script_cve_id("CVE-2019-11707", "CVE-2019-11708", "CVE-2019-11709", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713", "CVE-2019-11715", "CVE-2019-11717", "CVE-2019-11719", "CVE-2019-11729", "CVE-2019-11730", "CVE-2019-9811");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:21 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 17:02:19 +0000 (Tue, 02 Jul 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14124-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14124-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914124-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140868");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-July/005727.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2019:14124-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox to version ESR 60.8 fixes the following issues:

Security issues fixed:

- CVE-2019-9811: Sandbox escape via installation of malicious language pack (bsc#1140868).
- CVE-2019-11711: Script injection within domain through inner window reuse (bsc#1140868).
- CVE-2019-11712: Cross-origin POST requests can be made with NPAPI plugins by following 308 redirects (bsc#1140868).
- CVE-2019-11713: Use-after-free with HTTP/2 cached stream (bsc#1140868).
- CVE-2019-11729: Empty or malformed p256-ECDH public keys may trigger a segmentation fault (bsc#1140868).
- CVE-2019-11715: HTML parsing error can contribute to content XSS (bsc#1140868).
- CVE-2019-11717: Caret character improperly escaped in origins (bsc#1140868).
- CVE-2019-11719: Out-of-bounds read when importing curve25519 private key (bsc#1140868).
- CVE-2019-11730: Same-origin policy treats all files in a directory as having the same-origin (bsc#1140868).
- CVE-2019-11709: Multiple Memory safety bugs fixed (bsc#1140868).
- CVE-2019-11708: Fix sandbox escape using Prompt:Open (bsc#1138872).
- CVE-2019-11707: Fixed a type confusion vulnerability in Arrary.pop (bsc#1138614)

Non-security issues fixed:

- Fix broken language plugins (bsc#1137792)");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 11-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~60.8.0esr~78.43.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~60.8.0esr~78.43.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~60.8.0esr~78.43.2", rls:"SLES11.0SP4"))) {
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
