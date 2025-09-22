# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833826");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-24785");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 16:04:13 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:56:55 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for peazip (openSUSE-SU-2023:0071-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0071-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LZIRA2ZFJZWEVFCSMWHI56CKGCJG2A3D");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'peazip'
  package(s) announced via the openSUSE-SU-2023:0071-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for peazip fixes the following issues:

     peazip was updated to 9.1.0:

  * Major restyle in application's look &amp  feel and themes, and many
         usability improvements for the file manager, and archiving /
         extraction screens.

  * The scripting engine was refined, with the ability to adapt the syntax
         for a specific 7z version at runtime, and to export archive conversion
         tasks as scripts.

  * Support for TAR, Brotli, and Zstandard formats was improved.

  * Pea was updated to 1.12, fixing for CVE-2023-24785 (this fixes
         boo#1208468)

     Update to 9.0.0:

       BACKEND:

  * Pea 1.11.

       CODE:

  * Fixes, clean up of legacy code.

  * Improved speed and memory usage.

       FILE MANAGER:

  * GUI better adapts to size and preference changes.

  * Selecting one of the available tool bars (archive manager, file
         manager, image manager) restores its visibility if the Tool bar is
         hidden.

       EXTRACTION and ARCHIVING:

  * Added new options for 7z/p7zip backend.

  * Improved support for TAR format, and for formats used in combination
         with TAR.

  * Improved support for ZPAQ and *PAQ formats.

  * Updated compression preset scripts.

  * Updated plugin for PeaZip.

  - Update to 8.9.0:

       BACKEND

  * Pea 1.10

       CODE

  * Password Manager is now re-set only from Options   Settings
           Privacy, Reset Password Manager link

  * Various fixes and improvements

  * Correctly displays folder size inside ZIP archives if applicable

  * Cleanup of legacy code

  * Improved performances and memory management for browsing archives

  * Improved opening folders after task completion

  * Improved detecting root extraction directory

  * Archive conversion procedure now opens target directory only once,
           after final compression step

  * Task window can now show temporary extraction work path from context
           menu right-clicking on input and output links

       FILE MANAGER

  * Added progress bar while opening archive files supported through 7z
           backend  progress indicator is not visible when archive pre-browsing
           is disabled in Options   Settings   General, Performance group

  * Improved Clipboard panel, can display tems size and modification date

  * Improved quick navigation menu (on the left of the Address bar)

  * Can now set password/keyfile, and display if a password is set
   ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'peazip' package(s) on openSUSE Backports SLE-15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"peazip", rpm:"peazip~9.1.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"peazip-kf5", rpm:"peazip-kf5~9.1.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"peazip", rpm:"peazip~9.1.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"peazip-kf5", rpm:"peazip-kf5~9.1.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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