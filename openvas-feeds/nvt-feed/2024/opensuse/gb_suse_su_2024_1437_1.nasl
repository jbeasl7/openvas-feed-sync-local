# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856109");
  script_cve_id("CVE-2024-2609", "CVE-2024-3302", "CVE-2024-3852", "CVE-2024-3854", "CVE-2024-3857", "CVE-2024-3859", "CVE-2024-3861", "CVE-2024-3863", "CVE-2024-3864");
  script_tag(name:"creation_date", value:"2024-04-27 01:00:32 +0000 (Sat, 27 Apr 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-01-21 16:52:27 +0000 (Tue, 21 Jan 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1437-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1437-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241437-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222535");
  script_xref(name:"URL", value:"https://kb.cert.org/vuls/id/421644");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/035096.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2024:1437-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Update to Mozilla Thunderbird 115.10.1

Security fixes (MFSA 2024-20) (bsc#1222535):

- CVE-2024-3852: GetBoundName in the JIT returned the wrong object (bmo#1883542)
- CVE-2024-3854: Out-of-bounds-read after mis-optimized switch statement (bmo#1884552)
- CVE-2024-3857: Incorrect JITting of arguments led to use-after-free during garbage collection (bmo#1886683)
- CVE-2024-2609: Permission prompt input delay could expire when not in focus (bmo#1866100)
- CVE-2024-3859: Integer-overflow led to out-of-bounds-read in the OpenType sanitizer (bmo#1874489)
- CVE-2024-3861: Potential use-after-free due to AlignedBuffer self-move (bmo#1883158)
- CVE-2024-3863: Download Protections were bypassed by .xrm-ms files on Windows (bmo#1885855)
- CVE-2024-3302: Denial of Service using HTTP/2 CONTINUATION frames (bmo#1881183, [link moved to references])
- CVE-2024-3864: Memory safety bug fixed in Firefox 125, Firefox ESR 115.10, and Thunderbird 115.10 (bmo#1888333)

Other Fixes:
 * fixed: Thunderbird processes did not exit cleanly, user
 intervention was required via task manager (bmo#1891889)
 * unresolved: After changing password on an IMAP account, the
 account could become locked due to too many failed login
 attempts (bmo#1862111)
 * fixed: Creating a tag in General Settings with a number as
 the tag name did not work (bmo#1881124)
 * fixed: Quick Filter button selections did not persist after
 restart (bmo#1847265)
 * fixed: Collapsing and expanding message list headers
 sometimes caused header to scroll out of view (bmo#1862197)
 * fixed: Single message with no children inside a parent thread
 sometimes displayed incorrectly as a thread with a duplicate
 of itself as its child (bmo#1427546)
 * fixed: 'Get selected messages' menu items did not work
 (bmo#1867091)
 * fixed: 'Download and Sync Messages' dialog was too short when
 using Russian locale, obscuring OK button (bmo#1881795)
 * fixed: After changing password on an IMAP account, the
 account could become locked due to too many failed login
 attempts (bmo#1862111)
 * fixed: Retrieving multiline POP3 message from server failed
 if message chunk ended in newline instead of carriage return
 and newline (bmo#1883760)
 * fixed: IMAP, POP3, and SMTP Exchange autoconfiguration did
 not support encryption configuration (bmo#1876992)
 * fixed: Non-empty address book search bar interfered with
 displaying/editing contacts (bmo#1833031)
 * fixed: Deleting attendees from 'Invite Attendees' view
 removed attendees from view, but not from invite
 (bmo#1874450)
 * fixed: Splitter arrow between task list and task description
 did not behave as expected (bmo#1889562)
 * fixed: Performance improvements and code cleanup
 (bmo#1878257,bmo#1883550)
 * fixed: Security fixes
 * unresolved: Thunderbird processes did not exit cleanly, user
 intervention was required via task manager (bmo#1891889)");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.10.1~150200.8.157.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.10.1~150200.8.157.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.10.1~150200.8.157.1", rls:"openSUSELeap15.5"))) {
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
