# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833858");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2021-32055", "CVE-2022-1328");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-19 17:33:56 +0000 (Wed, 19 May 2021)");
  script_tag(name:"creation_date", value:"2024-03-04 07:34:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for neomutt (openSUSE-SU-2022:10020-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10020-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YAIJ2AOB7KV4ZEDS2ZHBBCKGSPYKSKDI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'neomutt'
  package(s) announced via the openSUSE-SU-2022:10020-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for neomutt fixes the following issues:
  neomutt was updated to 20220429:

  * Bug Fixes

  * Do not crash on an invalid use_threads/sort combination

  * Fix: stuck browser cursor

  * Resolve (move) the cursor after  edit-label

  * Index: fix menu size on new mail

  * Don't overlimit LMDB mmap size

  * OpenBSD y/n translation fix

  * Generic: split out OP_EXIT binding

  * Fix parsing of sendmail cmd

  * Fix: crash with menu_move_off=no

  * Newsrc: bugfix  nntp_user and nntp_pass ignored

  * Menu: ensure config changes cause a repaint

  * Mbox: fix sync duplicates

  * Make sure the index redraws all that's needed

  * Translations

  * 100% Chinese (Simplified)

  * 100% Czech

  * 100% German

  * 100% Hungarian

  * 100% Lithuanian

  * 100% Serbian

  * 100% Turkish

  * Docs

  * add missing pattern modifier ~I for external_search_command

  * Code

  * menu: eliminate custom_redraw()

  * modernise mixmaster

  * Kill global and Propagate display attach status through State-
  neomutt was updated to 20220415:

  * Security

  * Fix uudecode buffer overflow (CVE-2022-1328)

  * Features

  * Colours, colours, colours

  * Bug Fixes

  * Pager: fix pager_stop

  * Merge colours with normal

  * Color: disable mono command

  * Fix forwarding text attachments when honor_disposition is set

  * Pager: drop the nntp change-group bindings

  * Use mailbox_check flags coherently, add IMMEDIATE flag

  * Fix: tagging in attachment list

  * Fix: misalignment of mini-index

  * Make sure to update the menu size after a resort

  * Translations

  * 100% Hungarian

  * Build

  * Update acutest

  * Code

  * Unify pipe functions

  * Index: notify if navigation fails

  * Gui: set colour to be merged with normal

  * Fix: leak in tls_check_one_certificate()

  * Upstream

  * Flush iconv() in mutt_convert_string()

  * Fix integer overflow in mutt_convert_string()

  * Fix uudecode cleanup on unexpected eof
  update to 20220408:

  * Compose multipart emails

  * Fix screen mode after attempting decryption

  * imap: increase max size of oauth2 token

  * Fix autocrypt

  * Unify Alias/Query workflow

  * Fix colours

  * Say which file exists when saving attachments

  * Force SMTP authentication if `smtp_user` is set

  * Fix selecting the right email after limiting

  * Make sure we have enough memory for a new email

  * Don't overwrite with zeroes after unlinking the file

  * Fix crash when forwarding attachments

  * ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'neomutt' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"neomutt", rpm:"neomutt~20220429~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neomutt-doc", rpm:"neomutt-doc~20220429~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neomutt-lang", rpm:"neomutt-lang~20220429~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neomutt", rpm:"neomutt~20220429~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neomutt-doc", rpm:"neomutt-doc~20220429~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"neomutt-lang", rpm:"neomutt-lang~20220429~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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