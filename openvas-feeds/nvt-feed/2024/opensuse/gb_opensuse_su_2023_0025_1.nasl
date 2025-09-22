# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833194");
  script_version("2025-03-11T05:38:16+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-46169");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-06 20:05:03 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:32:55 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for cacti, cacti (openSUSE-SU-2023:0025-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0025-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QUYL2GI3BFKW22SLFY335X4U7WVAA4G4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti, cacti'
  package(s) announced via the openSUSE-SU-2023:0025-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cacti, cacti-spine fixes the following issues:

     cacti-spine 1.2.23:

  * Fix unexpected reindexing when using uptime as the reindex method

  * Spine should prevent the script server from connecting to remote when
       offline

  * Improve Script Server Timeout Logging

  * Add SQL_NO_CACHE to Spine Queries

     cacti 1.2.23, providing security fixes, feature improvements and bug fixes:

  * CVE-2022-46169: Unauthenticated Command Injection in Remote Agent
       (boo#1206185)

  * Security: Add .htaccess file to scripts folder

  * When using Single Sign-on Frameworks, revocation was not always detected
       in callbacks

  * Fixes to the installer, and compatibility with PHP and MySQL

  * Performance improvements for certain conditions

  * Various UI fixes

  * Bug fixes related to SNMP, RRDtools, and agents");

  script_tag(name:"affected", value:"'cacti, cacti' package(s) on openSUSE Backports SLE-15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.2.23~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.2.23~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.2.23~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.2.23~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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