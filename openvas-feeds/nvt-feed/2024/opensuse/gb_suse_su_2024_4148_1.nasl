# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856784");
  script_cve_id("CVE-2024-11691", "CVE-2024-11692", "CVE-2024-11693", "CVE-2024-11694", "CVE-2024-11695", "CVE-2024-11696", "CVE-2024-11697", "CVE-2024-11698", "CVE-2024-11699");
  script_tag(name:"creation_date", value:"2024-12-04 05:00:31 +0000 (Wed, 04 Dec 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:4148-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5|openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4148-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20244148-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233695");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-December/019900.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2024:4148-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

- Mozilla Thunderbird 128.5
 * fixed: IMAP could crash when reading cached messages
 * fixed: Enabling 'Show Folder Size' on Maildir profile could
 render Thunderbird unusable
 * fixed: Messages corrupted by folder compaction were only
 fixed by user intervention
 * fixed: Reading a message from past the end of an mbox file
 did not cause an error
 * fixed: View -> Folders had duplicate F access keys
 * fixed: Add-ons adding columns to the message list could fail
 and cause display issue
 * fixed: 'Empty trash on exit' and 'Expunge inbox on exit' did
 not always work
 * fixed: Selecting a display option in View -> Tasks did not
 apply in the Task interface
 * fixed: Security fixes
 MFSA 2024-68 (bsc#1233695)
 * CVE-2024-11691 Out-of-bounds write in Apple GPU drivers via WebGL
 * CVE-2024-11692 Select list elements could be shown over another site
 * CVE-2024-11693 Download Protections were bypassed by .library-ms files on Windows
 * CVE-2024-11694 CSP Bypass and XSS Exposure via Web Compatibility Shims
 * CVE-2024-11695 URL Bar Spoofing via Manipulated Punycode and Whitespace Characters
 * CVE-2024-11696 Unhandled Exception in Add-on Signature Verification
 * CVE-2024-11697 Improper Keypress Handling in Executable File Confirmation Dialog
 * CVE-2024-11698 Fullscreen Lock-Up When Modal Dialog Interrupts Transition on macOS
 * CVE-2024-11699 Memory safety bugs fixed in Firefox 133, Thunderbird 133, Firefox ESR 128.5, and Thunderbird 128.5

- Handle upstream changes with esr-prefix of desktop-file (bsc#1233650)");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.5.0~150200.8.191.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.5.0~150200.8.191.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.5.0~150200.8.191.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.5.0~150200.8.191.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.5.0~150200.8.191.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.5.0~150200.8.191.1", rls:"openSUSELeap15.6"))) {
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
