# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0405.1");
  script_cve_id("CVE-2024-11704", "CVE-2025-0510", "CVE-2025-1009", "CVE-2025-1010", "CVE-2025-1011", "CVE-2025-1012", "CVE-2025-1013", "CVE-2025-1014", "CVE-2025-1015", "CVE-2025-1016", "CVE-2025-1017");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-06 19:39:03 +0000 (Thu, 06 Feb 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0405-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0405-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250405-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236539");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020302.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2025:0405-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2025-1009: use-after-free in XSLT.
 - CVE-2025-1010: use-after-free in Custom Highlight.
 - CVE-2025-1011: a bug in WebAssembly code generation could result in a crash.
 - CVE-2025-1012: use-after-free during concurrent delazification.
 - CVE-2024-11704: potential double-free vulnerability in PKCS#7 decryption handling.
 - CVE-2025-1013: potential opening of private browsing tabs in normal browsing windows.
 - CVE-2025-1014: certificate length was not properly checked.
 - CVE-2025-1015: unsanitized address book fields.
 - CVE-2025-0510: address of e-mail sender can be spoofed by malicious email.
 - CVE-2025-1016: memory safety bugs.
 - CVE-2025-1017: memory safety bugs.

Other fixes:

 - fixed: images inside links could zoom when clicked instead of opening the link.
 - fixed: compacting an empty folder failed with write error.
 - fixed: compacting of IMAP folder with corrupted local storage failed with write error.
 - fixed: after restart, all restored tabs with opened PDFs showed the same attachment.
 - fixed: exceptions during CalDAV item processing would halt subsequent item handling.
 - fixed: context menu was unable to move email address to a different field.
 - fixed: link at about:rights pointed to Firefox privacy policy instead of Thunderbird's.
 - fixed: POP3 'fetch headers only' and 'get selected messages' could delete messages.
 - fixed: 'Search Online' checkbox in saved search properties was incorrectly disabled.
 - fixed: POP3 status message showed incorrect download count when messages were deleted.
 - fixed: space bar did not always advance to the next unread message.
 - fixed: folder creation or renaming failed due to incorrect preference settings.
 - fixed: forwarding/editing S/MIME drafts/templates unusable due to regression (bsc#1236411).
 - fixed: sort order in 'Search Messages' panel reset after search or on first launch.
 - fixed: reply window added an unnecessary third blank line at the top.
 - fixed: Thunderbird spell check box did not allow ENTER to accept suggested changes.
 - fixed: long email subject lines could overlap window control buttons on macOS.
 - fixed: flathub manifest link was not correct.
 - fixed: 'Prefer client-side email scheduling' needed to be selected twice.
 - fixed: duplicate invitations were sent if CALDAV calendar email case did not match.
 - fixed: visual and UX improvements.");

  script_tag(name:"affected", value:"'MozillaThunderbird' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~128.7.0~150200.8.200.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~128.7.0~150200.8.200.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~128.7.0~150200.8.200.1", rls:"openSUSELeap15.6"))) {
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
