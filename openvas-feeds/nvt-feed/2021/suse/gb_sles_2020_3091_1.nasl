# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3091.1");
  script_cve_id("CVE-2020-15673", "CVE-2020-15676", "CVE-2020-15677", "CVE-2020-15678", "CVE-2020-15683", "CVE-2020-15969");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:51 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-28 01:09:52 +0000 (Wed, 28 Oct 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3091-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3091-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203091-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird and mozilla-nspr' package(s) announced via the SUSE-SU-2020:3091-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaThunderbird and mozilla-nspr fixes the following issues:

Mozilla Thunderbird 78.4
 * new: MailExtensions: browser.tabs.sendMessage API added
 * new: MailExtensions: messageDisplayScripts API added
 * changed: Yahoo and AOL mail users using password authentication will
 be migrated to OAuth2
 * changed: MailExtensions: messageDisplay APIs extended to support
 multiple selected messages
 * changed: MailExtensions: compose.begin functions now support creating
 a message with attachments
 * fixed: Thunderbird could freeze when updating global search index
 * fixed: Multiple issues with handling of self-signed SSL certificates
 addressed
 * fixed: Recipient address fields in compose window could expand to fill
 all available space
 * fixed: Inserting emoji characters in message compose window caused
 unexpected behavior
 * fixed: Button to restore default folder icon color was not keyboard
 accessible
 * fixed: Various keyboard navigation fixes
 * fixed: Various color-related theme fixes
 * fixed: MailExtensions: Updating attachments with
 onBeforeSend.addListener() did not work MFSA 2020-47 (bsc#1177977)
 * CVE-2020-15969 Use-after-free in usersctp
 * CVE-2020-15683 Memory safety bugs fixed in Thunderbird 78.4

Mozilla Thunderbird 78.3.3
 * OpenPGP: Improved support for encrypting with subkeys
 * OpenPGP message status icons were not visible in message header pane
 * Creating a new calendar event did not require an event title

Mozilla Thunderbird 78.3.2 (bsc#1176899)
 * OpenPGP: Improved support for encrypting with subkeys
 * OpenPGP: Encrypted messages with international characters were
 sometimes displayed incorrectly
 * Single-click deletion of recipient pills with middle mouse button
 restored
 * Searching an address book list did not display results
 * Dark mode, high contrast, and Windows theming fixes

Mozilla Thunderbird 78.3.1
 * fix crash in nsImapProtocol::CreateNewLineFromSocket

Mozilla Thunderbird 78.3.0 MFSA 2020-44 (bsc#1176756)
 * CVE-2020-15677 Download origin spoofing via redirect
 * CVE-2020-15676 XSS when pasting attacker-controlled data into a
 contenteditable element
 * CVE-2020-15678 When recursing through layers while scrolling, an
 iterator may have become invalid, resulting in a potential use-after-
 free scenario
 * CVE-2020-15673 Memory safety bugs fixed in Thunderbird 78.3

update mozilla-nspr to version 4.25.1
 * The macOS platform code for shared library loading was changed to
 support macOS 11.
 * Dependency needed for the MozillaThunderbird udpate");

  script_tag(name:"affected", value:"'MozillaThunderbird and mozilla-nspr' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Workstation Extension 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.25.1~3.15.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit-debuginfo", rpm:"mozilla-nspr-32bit-debuginfo~4.25.1~3.15.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.25.1~3.15.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.25.1~3.15.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.25.1~3.15.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.25.1~3.15.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.25.1~3.15.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit-debuginfo", rpm:"mozilla-nspr-32bit-debuginfo~4.25.1~3.15.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.25.1~3.15.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.25.1~3.15.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.25.1~3.15.2", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.25.1~3.15.2", rls:"SLES15.0SP2"))) {
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
