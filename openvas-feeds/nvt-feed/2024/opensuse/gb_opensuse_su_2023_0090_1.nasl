# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833876");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-39331", "CVE-2022-39332", "CVE-2022-39333", "CVE-2022-39334", "CVE-2023-23942");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-15 02:02:50 +0000 (Wed, 15 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:12:23 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for nextcloud (openSUSE-SU-2023:0090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0090-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GFP6TNOFEBJRMI6THFF3YWBQRIFNJGVN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud'
  package(s) announced via the openSUSE-SU-2023:0090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nextcloud-desktop fixes the following issues:

     nextcloud-desktop was updated to 3.8.0:

  - Resize WebView widget once the loginpage rendered

  - Feature/secure file drop

  - Check German translation for wrong wording

  - L10n: Correct word

  - Fix displaying of file details button for local syncfileitem activities

  - Improve config upgrade warning dialog

  - Only accept folder setup page if overrideLocalDir is set

  - Update CHANGELOG.

  - Prevent ShareModel crash from accessing bad pointers

  - Bugfix/init value for pointers

  - Log to stdout when built in Debug config

  - Clean up account creation and deletion code

  - L10n: Added dot to end of sentence

  - L10n: Fixed grammar

  - Fix 'Create new folder' menu entries in settings not working correctly
         on macOS

  - Ci/clang tidy checks init variables

  - Fix share dialog infinite loading

  - Fix edit locally job not finding the user account: wrong user id

  - Skip e2e encrypted files with empty filename in metadata

  - Use new connect syntax

  - Fix avatars not showing up in settings dialog account actions until
         clicked on

  - Always discover blacklisted folders to avoid data loss when modifying
         selectivesync list.

  - Fix infinite loading in the share dialog when public link shares are
         disabled on the server

  - With cfapi when dehydrating files add missing flag

  - Fix text labels in Sync Status component

  - Display 'Search globally' as the last sharees list element

  - Fix display of 2FA notification.

  - Bugfix/do not restore virtual files

  - Show server name in tray main window

  - Add Ubuntu Lunar

  - Debian build classification 'beta' cannot override 'release'.

  - Update changelog

  - Follow shouldNotify flag to hide notifications when needed

  - Bugfix/stop after creating config file

  - E2EE cut extra zeroes from derypted byte array.

  - When local sync folder is overridden, respect this choice

  - Feature/e2ee fixes

  - This also fix security issues:

  - (boo#1205798, CVE-2022-39331)

  - Arbitrary HyperText Markup Language injection in notifications

  - (boo#1205799, CVE-2022-39332)

  - Arbitrary HyperText Markup Language injection in user status and
           information

  - (boo#1205800, CVE-2022-39333)

  - Arbitrary HyperText Markup Language injection in desktop client
           application

  - (boo#1205801, CVE-2022-39 ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'nextcloud' package(s) on openSUSE Backports SLE-15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libnextcloudsync-devel", rpm:"libnextcloudsync-devel~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnextcloudsync0", rpm:"libnextcloudsync0~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-desktop", rpm:"nextcloud-desktop~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-desktop-dolphin", rpm:"nextcloud-desktop-dolphin~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caja-extension-nextcloud", rpm:"caja-extension-nextcloud~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloudproviders-extension-nextcloud", rpm:"cloudproviders-extension-nextcloud~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-extension-nextcloud", rpm:"nautilus-extension-nextcloud~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nemo-extension-nextcloud", rpm:"nemo-extension-nextcloud~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-desktop-doc", rpm:"nextcloud-desktop-doc~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-desktop-lang", rpm:"nextcloud-desktop-lang~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnextcloudsync-devel", rpm:"libnextcloudsync-devel~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnextcloudsync0", rpm:"libnextcloudsync0~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-desktop", rpm:"nextcloud-desktop~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-desktop-dolphin", rpm:"nextcloud-desktop-dolphin~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caja-extension-nextcloud", rpm:"caja-extension-nextcloud~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cloudproviders-extension-nextcloud", rpm:"cloudproviders-extension-nextcloud~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-extension-nextcloud", rpm:"nautilus-extension-nextcloud~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nemo-extension-nextcloud", rpm:"nemo-extension-nextcloud~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-desktop-doc", rpm:"nextcloud-desktop-doc~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-desktop-lang", rpm:"nextcloud-desktop-lang~3.8.0~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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