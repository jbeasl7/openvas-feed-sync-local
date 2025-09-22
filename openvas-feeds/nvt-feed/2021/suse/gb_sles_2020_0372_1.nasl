# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0372.1");
  script_cve_id("CVE-2019-9853");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-02 14:22:24 +0000 (Wed, 02 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0372-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0372-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200372-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152684");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-February/006474.html");
  script_xref(name:"URL", value:"https://wiki.documentfoundation.org/ReleaseNotes/6.3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibreOffice' package(s) announced via the SUSE-SU-2020:0372-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update libreoffice and libraries fixes the following issues:

LibreOffice was updated to 6.3.3 (jsc#SLE-8705), bringing many bug and stability fixes.

More information for the 6.3 release at: [link moved to references]

Security issue fixed:

- CVE-2019-9853: Fixed an issue where by executing macros, the security settings
 could have been bypassed (bsc#1152684).

Other issues addressed:

- Dropped disable-kde4 switch, since it is no longer known by configure
- Disabled gtk2 because it will be removed in future releases
- librelogo is now a standalone sub-package (bsc#1144522).
- Partial fixes for an issue where Table(s) from DOCX showed wrong
 position or color (bsc#1061210).

cmis-client was updated to 0.5.2:

 * Removed header for Uuid's sha1 header(bsc#1105173).
 * Fixed Google Drive login
 * Added support for Google Drive two-factor authentication
 * Fixed access to SharePoint root folder
 * Limited the maximal number of redirections to 20
 * Switched library implementation to C++11 (the API remains C++98-compatible)
 * Fixed encoding of OAuth2 credentials
 * Dropped cppcheck run from 'make check'. A new 'make cppcheck' target was created for it
 * Added proper API symbol exporting
 * Speeded up building of tests a bit
 * Fixed a few issues found by coverity and cppcheck

libixion was updated to 0.15.0:

 * Updated for new liborcus
 * Switched to spdlog for compile-time debug log outputs
 * Fixed various issues

libmwaw was updated 0.3.15:

 * Fixed fuzzing issues

liborcus was updated to 0.15.3:

 * Fixed various xml related bugs
 * Improved performance
 * Fixed multiple parser issues
 * Added map and structure mode to orcus-json
 * Other improvements and fixes

mdds was updated to 1.5.0:

 * API changed to 1.5
 * Moved the API incompatibility notes from README to the rst doc.
 * Added the overview section for flat_segment_tree.

myspell-dictionaries was updated to 20191016:

 * Updated Slovenian thesaurus
 * Updated the da_DK dictionary
 * Removed the abbreviations from Thai hunspell dictionary
 * Updated the English dictionaries
 * Fixed the logo management for 'ca'

spdlog was updated to 0.16.3:

 * Fixed sleep issue under MSVC that happens when changing
 the clock backwards
 * Ensured that macros always expand to expressions
 * Added global flush_on function

bluez changes:

 * lib: Changed bluetooth.h to compile in strict C

gperf was updated to 3.1:

 * The generated C code is now in ANSI-C by default.
 * Added option --constants-prefix.
 * Added declaration %define constants-prefix.");

  script_tag(name:"affected", value:"'LibreOffice' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.13~5.20.6", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluetooth3", rpm:"libbluetooth3~5.13~5.20.6", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.13~5.20.6", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluetooth3", rpm:"libbluetooth3~5.13~5.20.6", rls:"SLES12.0SP5"))) {
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
