# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0374.1");
  script_cve_id("CVE-2024-11704", "CVE-2025-1009", "CVE-2025-1010", "CVE-2025-1011", "CVE-2025-1012", "CVE-2025-1013", "CVE-2025-1014", "CVE-2025-1016", "CVE-2025-1017");
  script_tag(name:"creation_date", value:"2025-02-07 04:29:55 +0000 (Fri, 07 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-06 19:39:03 +0000 (Thu, 06 Feb 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0374-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0374-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250374-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236539");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020274.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2025:0374-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox to 128.7esr fixes the following issues:

* MFSA 2025-09
 * CVE-2025-1009 (bmo#1936613)
 Use-after-free in XSLT
 * CVE-2025-1010 (bmo#1936982)
 Use-after-free in Custom Highlight
 * CVE-2025-1011 (bmo#1936454)
 A bug in WebAssembly code generation could result in a crash
 * CVE-2025-1012 (bmo#1939710)
 Use-after-free during concurrent delazification
 * CVE-2024-11704 (bmo#1899402)
 Potential double-free vulnerability in PKCS#7 decryption
 handling
 * CVE-2025-1013 (bmo#1932555)
 Potential opening of private browsing tabs in normal browsing
 windows
 * CVE-2025-1014 (bmo#1940804)
 Certificate length was not properly checked
 * CVE-2025-1016 (bmo#1936601, bmo#1936844, bmo#1937694,
 bmo#1938469, bmo#1939583, bmo#1940994)
 Memory safety bugs fixed in Firefox 135, Thunderbird 135,
 Firefox ESR 115.20, Firefox ESR 128.7, Thunderbird 115.20,
 and Thunderbird 128.7
 * CVE-2025-1017 (bmo#1926256, bmo#1935471, bmo#1935984)
 Memory safety bugs fixed in Firefox 135, Thunderbird 135,
 Firefox ESR 128.7, and Thunderbird 128.7");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~128.7.0~150200.152.170.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~128.7.0~150200.152.170.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~128.7.0~150200.152.170.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~128.7.0~150200.152.170.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~128.7.0~150200.152.170.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~128.7.0~150200.152.170.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~128.7.0~150200.152.170.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~128.7.0~150200.152.170.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~128.7.0~150200.152.170.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~128.7.0~150200.152.170.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~128.7.0~150200.152.170.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~128.7.0~150200.152.170.1", rls:"SLES15.0SP5"))) {
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
