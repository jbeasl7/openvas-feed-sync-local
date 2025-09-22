# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833216");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-4051", "CVE-2023-4053", "CVE-2023-4573", "CVE-2023-4574", "CVE-2023-4575", "CVE-2023-4576", "CVE-2023-4577", "CVE-2023-4578", "CVE-2023-4580", "CVE-2023-4581", "CVE-2023-4582", "CVE-2023-4583", "CVE-2023-4584", "CVE-2023-4585", "CVE-2023-4863");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-18 17:48:44 +0000 (Mon, 18 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:00:18 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (SUSE-SU-2023:3664-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3664-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/D4SOESMQ2SO6Q5S55242QF533SMUVT3G");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the SUSE-SU-2023:3664-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  Security fixes:

  * Mozilla Thunderbird 115.2.2 (MFSA 2023-40, bsc#1215245)

  * CVE-2023-4863: Fixed heap buffer overflow in libwebp (bmo#1852649).

  * Mozilla Thunderbird 115.2 (MFSA 2023-38, bsc#1214606)

  * CVE-2023-4573: Memory corruption in IPC CanvasTranslator (bmo#1846687)

  * CVE-2023-4574: Memory corruption in IPC ColorPickerShownCallback
      (bmo#1846688)

  * CVE-2023-4575: Memory corruption in IPC FilePickerShownCallback
      (bmo#1846689)

  * CVE-2023-4576: Integer Overflow in RecordedSourceSurfaceCreation
      (bmo#1846694)

  * CVE-2023-4577: Memory corruption in JIT UpdateRegExpStatics (bmo#1847397)

  * CVE-2023-4051: Full screen notification obscured by file open dialog
      (bmo#1821884)

  * CVE-2023-4578: Error reporting methods in SpiderMonkey could have triggered
      an Out of Memory Exception (bmo#1839007)

  * CVE-2023-4053: Full screen notification obscured by external program
      (bmo#1839079)

  * CVE-2023-4580: Push notifications saved to disk unencrypted (bmo#1843046)

  * CVE-2023-4581: XLL file extensions were downloadable without warnings
      (bmo#1843758)

  * CVE-2023-4582: Buffer Overflow in WebGL glGetProgramiv (bmo#1773874)

  * CVE-2023-4583: Browsing Context potentially not cleared when closing Private
      Window (bmo#1842030)

  * CVE-2023-4584: Memory safety bugs fixed in Firefox 117, Firefox ESR 102.15,
      Firefox ESR 115.2, Thunderbird 102.15, and Thunderbird 115.2 (bmo#1843968,
      bmo#1845205, bmo#1846080, bmo#1846526, bmo#1847529)

  * CVE-2023-4585: Memory safety bugs fixed in Firefox 117, Firefox ESR 115.2,
      and Thunderbird 115.2 (bmo#1751583, bmo#1833504, bmo#1841082, bmo#1847904,
      bmo#1848999)

  Other fixes:

  Mozilla Thunderbird 115.2.1 * new: Column separators are now shown between all
  columns in tree view (bmo#1847441) * fixed: Crash reporter did not work in
  Thunderbird Flatpak (bmo#1843102) * fixed: New mail notification always opened
  message in message pane, even if pane was disabled (bmo#1840092) * fixed: After
  moving an IMAP message to another folder, the incorrect message was selected in
  the message list (bmo#1845376) * fixed: Adding a tag to an IMAP message opened
  in a tab failed (bmo#1844452) * fixed: Junk/Spam folders were not always shown
  in Unified Folders mode (bmo#1838672) * fixed: Middle-clicking a folder or
  message did not open it in a background tab, as in previous versions
  (bmo#1842482) * fixed: Settings tab visual improvements: Advanced Fonts di ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~115.2.2~150200.8.130.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.2.2~150200.8.130.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.2.2~150200.8.130.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~115.2.2~150200.8.130.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.2.2~150200.8.130.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~115.2.2~150200.8.130.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.2.2~150200.8.130.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.2.2~150200.8.130.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~115.2.2~150200.8.130.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.2.2~150200.8.130.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~115.2.2~150200.8.130.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.2.2~150200.8.130.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.2.2~150200.8.130.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~115.2.2~150200.8.130.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.2.2~150200.8.130.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~115.2.2~150200.8.130.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.2.2~150200.8.130.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.2.2~150200.8.130.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~115.2.2~150200.8.130.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.2.2~150200.8.130.1", rls:"openSUSELeap15.5"))) {
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