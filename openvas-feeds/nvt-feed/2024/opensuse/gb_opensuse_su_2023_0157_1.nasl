# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833296");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2023-32784");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-26 16:25:22 +0000 (Fri, 26 May 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:33:15 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for keepass (openSUSE-SU-2023:0157-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0157-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YO3KDTWTM4LYCKXITB6HKBAPXRJFQLJ6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keepass'
  package(s) announced via the openSUSE-SU-2023:0157-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for keepass fixes the following issues:

     Update to 2.54

  * Security:

         + Improved process memory protection of secure edit controls
           (CVE-2023-32784, boo#1211397).

  * New Features:

         + Triggers, global URL overrides, password generator profiles and a
           few more settings are now stored in the enforced configuration file.
         + Added dialog 'Enforce Options (All Users)' (menu 'Tools'
           'Advanced Tools'  'Enforce Options'), which facilitates storing
           certain options in the enforced configuration file.
         + In report dialogs, passwords (and other sensitive data) are now
           hidden using asterisks by default (if hiding is activated in the
           main window)  the hiding can be toggled using the new '***' button
           in the toolbar.
         + The 'Print' command in most report dialogs now requires the 'Print'
           application policy flag, and the master key must be entered if the
           'Print - No Key Repeat' application policy flag is deactivated.
         + The 'Export' command in most report dialogs now requires the
           'Export' application policy flag, and the master key must be entered.
         + Single line edit dialogs now support hiding the value using
           asterisks.
         + Commands that require elevation now have a shield icon like on
           Windows.
         + TrlUtil: added 'Move Selected Unused Text to Dialog Control' command.

  * Improvements:

  * The content mode of the configuration elements
           '/Configuration/Application/TriggerSystem',
           '/Configuration/Integration/UrlSchemeOverrides' and
           '/Configuration/PasswordGenerator/UserProfiles' is now 'Replace' by
           default.

  * The built-in override for the 'ssh' URI scheme is now deactivated by
           default (it can be activated in the 'URL Overrides' dialog).

  * When opening the password generator dialog without a derived
           profile, the '(Automatically generated passwords for new entries)'
           profile is now selected by default, if profiles are enabled
           (otherwise the default profile is used).

  * The clipboard workarounds are now disabled by default (they are not
           needed anymore on most systems).

  * Improved clipboard clearing.

  * Improved starting of an elevated process.

  * Bugfixes:

         + In report dialogs, the 'Print' and 'Export' commands now always use
           the actual data (in previous versions, asteris ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'keepass' package(s) on openSUSE Backports SLE-15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"keepass", rpm:"keepass~2.54~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keepass", rpm:"keepass~2.54~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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