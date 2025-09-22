# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0242.1");
  script_cve_id("CVE-2024-0741", "CVE-2024-0742", "CVE-2024-0746", "CVE-2024-0747", "CVE-2024-0749", "CVE-2024-0750", "CVE-2024-0751", "CVE-2024-0753", "CVE-2024-0755");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 22:47:49 +0000 (Mon, 29 Jan 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0242-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0242-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240242-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218955");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-January/017761.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird' package(s) announced via the SUSE-SU-2024:0242-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird fixes the following issues:

Update to Mozilla Thunderbird 115.7 (MFSA 2024-04) (bsc#1218955):

 - CVE-2024-0741: Out of bounds write in ANGLE
 - CVE-2024-0742: Failure to update user input timestamp
 - CVE-2024-0746: Crash when listing printers on Linux
 - CVE-2024-0747: Bypass of Content Security Policy when directive unsafe-inline was set
 - CVE-2024-0749: Phishing site popup could show local origin in address bar
 - CVE-2024-0750: Potential permissions request bypass via clickjacking
 - CVE-2024-0751: Privilege escalation through devtools
 - CVE-2024-0753: HSTS policy on subdomain could bypass policy of upper domain
 - CVE-2024-0755: Memory safety bugs fixed in Firefox 122, Firefox ESR 115.7, and Thunderbird 115.7

Other fixes:

 * new: Autocrypt Gossip key distribution added (bmo#1853674)
 * fixed: When starting Thunderbird, unread message count did
 not appear on collapsed accounts (bmo#1862774)
 * fixed: Blank window was sometimes displayed when starting
 Thunderbird (bmo#1870817)
 * fixed: Thunderbird '--chrome' flag incorrectly opened extra
 messenger.xhtml (bmo#1866915)
 * fixed: Add-ons did not start correctly when opening
 Thunderbird from other programs (bmo#1800423)
 * fixed: Drag-and-drop installation of add-ons did not work if
 Add-ons Manager was opened from Unified Toolbar (bmo#1862978)
 * fixed: Double-clicking empty space in message pane
 incorrectly opened the currently selected message
 (bmo#1867407)
 * fixed: Canceling SMTP send before progress reached 100% did
 not stop message from sending (bmo#1816540)
 * fixed: PDF attachments open in a separate tab did not always
 restore correctly after restarting Thunderbird (bmo#1846054)
 * fixed: Some OpenPGP dialogs were too small for their contents
 (bmo#1870809)
 * fixed: Account Manager did not work with hostnames entered as
 punycode (bmo#1870720,bmo#1872632)
 * fixed: Downloading complete message from POP3 headers caused
 message tab/window to close when 'Close message window/tab on
 move or delete' was enabled (bmo#1861886)
 * fixed: Some ECC GPG keys could not be exported (bmo#1867765)
 * fixed: Contacts deleted from mailing list view still visible
 in Details view (bmo#1799362)
 * fixed: After selecting contacts in Address Book and starting
 a new search, the search results list did not update
 (bmo#1812726)
 * fixed: Various UX and visual improvements (bmo#1866061,bmo#18
 67169,bmo#1867728,bmo#1868079,bmo#1869519,bmo#1832149,bmo#185
 6495,bmo#1861210,bmo#1861286,bmo#1863296,bmo#1864979)
 * fixed: Security fixes

- Mozilla Thunderbird 115.6.1
 * new: OAuth2 now supported for comcast.net (bmo#1844810)
 * fixed: High CPU usage sometimes occurred with IMAP CONDSTORE
 (conditional STORE) enabled (bmo#1839256)
 * fixed: Replying to a collapsed thread via keyboard shortcut
 (Ctrl+R/Cmd+R) opened a reply for every message in the thread
 (bmo#1866819)
 * fixed: Enabling ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~115.7.0~150200.8.145.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~115.7.0~150200.8.145.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~115.7.0~150200.8.145.1", rls:"openSUSELeap15.5"))) {
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
