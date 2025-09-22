# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3614.1");
  script_cve_id("CVE-2024-8900", "CVE-2024-9392", "CVE-2024-9393", "CVE-2024-9394", "CVE-2024-9396", "CVE-2024-9397", "CVE-2024-9398", "CVE-2024-9399", "CVE-2024-9400", "CVE-2024-9401", "CVE-2024-9402", "CVE-2024-9680");
  script_tag(name:"creation_date", value:"2024-10-15 04:28:23 +0000 (Tue, 15 Oct 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-16 15:07:36 +0000 (Wed, 16 Oct 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3614-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3614-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243614-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231413");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-October/019594.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2024:3614-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Update to Firefox Extended Support Release 128.3.1 ESR MFSA 2024-51 (bsc#1231413)

- CVE-2024-9680: Use-after-free in Animation timeline (bmo#1923344)

Also includes the following CVEs from MFSA 2024-47 (bsc#1230979)

- CVE-2024-9392: Compromised content process can bypass site isolation (bmo#1899154, bmo#1905843)
- CVE-2024-9393: Cross-origin access to PDF contents through multipart responses (bmo#1918301)
- CVE-2024-9394: Cross-origin access to JSON contents through multipart responses (bmo#1918874)
- CVE-2024-8900: Clipboard write permission bypass (bmo#1872841)
- CVE-2024-9396: Potential memory corruption may occur when cloning certain objects (bmo#1912471)
- CVE-2024-9397: Potential directory upload bypass via clickjacking (bmo#1916659)
- CVE-2024-9398: External protocol handlers could be enumerated via popups (bmo#1881037)
- CVE-2024-9399: Specially crafted WebTransport requests could lead to denial of service (bmo#1907726)
- CVE-2024-9400: Potential memory corruption during JIT compilation (bmo#1915249)
- CVE-2024-9401: Memory safety bugs fixed in Firefox 131, Firefox ESR 115.16, Firefox ESR 128.3, Thunderbird 131, and Thunderbird 128.3 (bmo#1872744, bmo#1897792, bmo#1911317, bmo#1916476)
- CVE-2024-9402: Memory safety bugs fixed in Firefox 131, Firefox ESR 128.3, Thunderbird 131, and Thunderbird 128.3i (bmo#1872744, bmo#1897792, bmo#1911317, bmo#1913445, bmo#1914106, bmo#1914475, bmo#1914963, bmo#1915008, bmo#1916476)");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~128.3.1~150200.152.155.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~128.3.1~150200.152.155.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~128.3.1~150200.152.155.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~128.3.1~150200.152.155.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~128.3.1~150200.152.155.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~128.3.1~150200.152.155.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~128.3.1~150200.152.155.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~128.3.1~150200.152.155.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~128.3.1~150200.152.155.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~128.3.1~150200.152.155.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~128.3.1~150200.152.155.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~128.3.1~150200.152.155.1", rls:"SLES15.0SP4"))) {
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
