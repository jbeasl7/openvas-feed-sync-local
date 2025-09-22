# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833418");
  script_version("2025-03-11T05:38:16+0000");
  script_cve_id("CVE-2022-0813", "CVE-2022-23807", "CVE-2022-23808", "CVE-2023-25727");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-12 04:23:44 +0000 (Sat, 12 Mar 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:44:43 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for phpMyAdmin (openSUSE-SU-2023:0047-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0047-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VQ5VVS2CGDQ32RHYLQQZFFFADPEZO6KM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the openSUSE-SU-2023:0047-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for phpMyAdmin fixes the following issues:

     phpMyAdmin was updated to 5.2.1

     This is a security and bufix release.

  * Security:

  - Fix (PMASA-2023-01, CWE-661, boo#1208186, CVE-2023-25727) Fix an XSS
         attack through the drag-and-drop upload feature.

  * Bugfixes:

  - issue #17522 Fix case where the routes cache file is invalid

  - issue #17506 Fix error when configuring 2FA without XMLWriter or
         Imagick

  - issue        Fix blank page when some error occurs

  - issue #17519 Fix Export pages not working in certain conditions

  - issue #17496 Fix error in table operation page when partitions are
         broken

  - issue #17386 Fix system memory and system swap values on Windows

  - issue #17517 Fix Database Server panel not getting hidden by
         ShowServerInfo configuration directive

  - issue #17271 Fix database names not showing on Processes tab

  - issue #17424 Fix export limit size calculation

  - issue #17366 Fix refresh rate popup on Monitor page

  - issue #17577 Fix monitor charts size on RTL languages

  - issue #17121 Fix password_hash function incorrectly adding single
         quotes to password before hashing

  - issue #17586 Fix statistics not showing for empty databases

  - issue #17592 Clicking on the New index link on the sidebar does not
         throw an error anymore

  - issue #17584 It's now possible to browse a database that includes two
         % in its name

  - issue        Fix PHP 8.2 deprecated string interpolation syntax

  - issue        Some languages are now correctly detected from the HTTP
         header

  - issue #17617 Sorting is correctly remembered when
         $cfg['RememberSorting'] is true

  - issue #17593 Table filtering now works when action buttons are on the
         right side of the row

  - issue #17388 Find and Replace using regex now makes a valid query if
         no matching result set found

  - issue #17551 Enum/Set editor will not fail to open when creating a new
         column

  - issue #17659 Fix error when a database group is named tables, views,
         functions, procedures or events

  - issue #17673 Allow empty values to be inserted into columns

  - issue #17620 Fix error handling at phpMyAdmin startup for the JS SQL
         console

  - issue        Fixed debug queries console broken UI for query time and
         group count

  - issue        Fixed escaping of SQL query and errors for the debug
         console

  - issue ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'phpMyAdmin' package(s) on openSUSE Backports SLE-15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~5.2.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin-apache", rpm:"phpMyAdmin-apache~5.2.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin-lang", rpm:"phpMyAdmin-lang~5.2.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~5.2.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin-apache", rpm:"phpMyAdmin-apache~5.2.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin-lang", rpm:"phpMyAdmin-lang~5.2.1~bp154.2.3.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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