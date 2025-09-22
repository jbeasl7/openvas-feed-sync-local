# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1002.1");
  script_cve_id("CVE-2023-5388", "CVE-2024-0743", "CVE-2024-1546", "CVE-2024-1547", "CVE-2024-1548", "CVE-2024-1549", "CVE-2024-1550", "CVE-2024-1551", "CVE-2024-1552", "CVE-2024-1553", "CVE-2024-2605", "CVE-2024-2607", "CVE-2024-2608", "CVE-2024-2610", "CVE-2024-2611", "CVE-2024-2612", "CVE-2024-2614", "CVE-2024-2616", "CVE-2024-29944");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-25 14:47:29 +0000 (Tue, 25 Feb 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1002-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1002-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241002-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221850");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-March/018221.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2024:1002-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

Firefox Extended Support Release 115.9.1esr ESR MFSA 2024-16 (bsc#1221850).

- CVE-2024-29944: Privileged JavaScript Execution via Event Handlers (bmo#1886852).


Firefox Extended Support Release 115.9.0 ESR (bsc#1221327):

- CVE-2024-0743: Crash in NSS TLS method (bmo#1867408).
- CVE-2024-2605: Windows Error Reporter could be used as a Sandbox escape
 vector (bmo#1872920).
- CVE-2024-2607: JIT code failed to save return registers on Armv7-A (bmo#1879939).
- CVE-2024-2608: Integer overflow could have led to out of bounds write (bmo#1880692).
- CVE-2024-2616: Improve handling of out-of-memory conditions in ICU (bmo#1846197).
- CVE-2023-5388: NSS susceptible to timing attack against RSA decryption (bmo#1780432).
- CVE-2024-2610: Improper handling of html and body tags enabled CSP nonce
 leakage (bmo#1871112).
- CVE-2024-2611: Clickjacking vulnerability could have led to a user
 accidentally granting permissions (bmo#1876675).
- CVE-2024-2612: Self referencing object could have potentially led to a use-
 after-free (bmo#1879444).
- CVE-2024-2614: Memory safety bugs fixed in Firefox 124, Firefox ESR 115.9,
 and Thunderbird 115.9 (bmo#1685358, bmo#1861016, bmo#1880405,
 bmo#1881093).");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~115.9.1~150200.152.131.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~115.9.1~150200.152.131.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~115.9.1~150200.152.131.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~115.9.1~150200.152.131.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~115.9.1~150200.152.131.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~115.9.1~150200.152.131.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~115.9.1~150200.152.131.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~115.9.1~150200.152.131.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~115.9.1~150200.152.131.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~115.9.1~150200.152.131.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~115.9.1~150200.152.131.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~115.9.1~150200.152.131.1", rls:"SLES15.0SP4"))) {
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
