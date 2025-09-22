# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833224");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-5168", "CVE-2023-5169", "CVE-2023-5171", "CVE-2023-5174", "CVE-2023-5176", "CVE-2023-5217");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-29 15:17:47 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:15:18 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (SUSE-SU-2023:4016-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4016-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AVCTQ6EA2GEPJPY2EXNNY36DK6BIFWXZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the SUSE-SU-2023:4016-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

  Security fixes: - CVE-2023-5217: Fixed a heap buffer overflow in libvpx.
  (bsc#1215814) - CVE-2023-5168: Out-of-bounds write in FilterNodeD2D1.
  (bsc#1215575) - CVE-2023-5169: Out-of-bounds write in PathOps. (bsc#1215575) -
  CVE-2023-5171: Use-after-free in Ion Compiler. (bsc#1215575) - CVE-2023-5174:
  Double-free in process spawning on Windows. (bsc#1215575) - CVE-2023-5176:
  Memory safety bugs fixed in Firefox 118, Firefox ESR 115.3, and Thunderbird
  115.3. (bsc#1215575)

  Other fixes:

  * Mozilla Thunderbird 115.3.1

  * fixed: In Unified Folders view, some folders had incorrect unified folder
      parent (bmo#1852525)

  * fixed: 'Edit message as new' did not restore encrypted subject from selected
      message (bmo#1788534)

  * fixed: Importing some CalDAV calendars with yearly recurrence events caused
      Thunderbird to freeze (bmo#1850732)

  * fixed: Security fixes MFSA 2023-44 (bsc#1215814)

  * CVE-2023-5217 (bmo#1855550) Heap buffer overflow in libvpx

  * Mozilla Thunderbird 115.3

  * fixed: Thunderbird could not import profiles with hostname ending in dot
      ('.') (bmo#1825374)

  * fixed: Message header was occasionally missing in message preview
      (bmo#1840943)

  * fixed: Setting an existing folder's type flag did not add descendant folders
      to the Unified Folders view (bmo#1848904)

  * fixed: Thunderbird did not always delete all temporary mail files, sometimes
      preventing messages from being sent (bmo#673703)

  * fixed: Status bar in Message Compose window could not be hidden
      (bmo#1806860)

  * fixed: Message header was intermittently missing from message preview
      (bmo#1840943)

  * fixed: OAuth2 did not work on some profiles created in Thunderbird 102.6.1
      or earlier (bmo#1814823)

  * fixed: In Vertical View, decrypted subject lines were displayed as ellipsis
      ('...') in message list (bmo#1831764)

  * fixed: Condensed address preference (mail.showCondensedAddresses) did not
      show condensed addresses in message list (bmo#1831280)

  * fixed: Spam folder could not be assigned non-ASCII names with IMAP UTF-8
      enabled (bmo#1816332)

  * fixed: Message header was not displayed until images finished loading,
      causing noticeable delay for messages containing large images (bmo#1851871)

  * fixed: Large SVG favicons did not display on RSS feeds (bmo#1853895)

  * fixed: Context menu items did not display a hover background color
      (bmo#1852732)

  * fixed: Security fixes MFSA 2023- ...

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~115.3.1~150200.8.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.3.1~150200.8.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.3.1~150200.8.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~115.3.1~150200.8.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.3.1~150200.8.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~115.3.1~150200.8.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.3.1~150200.8.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.3.1~150200.8.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~115.3.1~150200.8.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.3.1~150200.8.133.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~115.3.1~150200.8.133.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.3.1~150200.8.133.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.3.1~150200.8.133.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~115.3.1~150200.8.133.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.3.1~150200.8.133.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~115.3.1~150200.8.133.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.3.1~150200.8.133.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.3.1~150200.8.133.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~115.3.1~150200.8.133.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.3.1~150200.8.133.1", rls:"openSUSELeap15.5"))) {
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