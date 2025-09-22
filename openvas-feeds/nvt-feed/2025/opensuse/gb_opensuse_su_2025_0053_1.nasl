# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0053.1");
  script_cve_id("CVE-2024-27628", "CVE-2024-34508", "CVE-2024-34509", "CVE-2024-47796", "CVE-2024-52333");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-06-25T05:41:02+0000");
  script_tag(name:"last_modification", value:"2025-06-25 05:41:02 +0000 (Wed, 25 Jun 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-24 13:44:55 +0000 (Tue, 24 Jun 2025)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0053-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/WGCW42LVEP5RLYCJ2ZF4ZZWGFA4Y2VOK/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235811");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dcmtk' package(s) announced via the openSUSE-SU-2025:0053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dcmtk fixes the following issues:

Update to 3.6.9. See DOCS/CHANGES.368 for the full list of changes

Security issues fixed:

- CVE-2024-27628: Fixed buffer overflow via the EctEnhancedCT method (boo#1227235)
- CVE-2024-34508: Fixed a segmentation fault via an invalid DIMSE message (boo#1223925)
- CVE-2024-34509: Fixed segmentation fault via an invalid DIMSE message (boo#1223943)
- CVE-2024-47796: Fixed out-of-bounds write due to improper array index validation in the nowindow functionality (boo#1235810)
- CVE-2024-52333: Fixed out-of-bounds write due to improper array index validation in the determineMinMax functionality (boo#1235811)");

  script_tag(name:"affected", value:"'dcmtk' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dcmtk", rpm:"dcmtk~3.6.9~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dcmtk-devel", rpm:"dcmtk-devel~3.6.9~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdcmtk19", rpm:"libdcmtk19~3.6.9~bp156.4.3.1", rls:"openSUSELeap15.6"))) {
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
