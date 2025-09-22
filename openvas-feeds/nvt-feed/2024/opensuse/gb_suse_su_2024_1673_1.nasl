# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856149");
  script_cve_id("CVE-2020-35654", "CVE-2021-23437", "CVE-2021-25289", "CVE-2021-25290", "CVE-2021-25292", "CVE-2021-25293", "CVE-2021-27921", "CVE-2021-27922", "CVE-2021-27923", "CVE-2021-34552", "CVE-2022-22815", "CVE-2022-22816");
  script_tag(name:"creation_date", value:"2024-05-24 01:00:24 +0000 (Fri, 24 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 12:28:43 +0000 (Fri, 16 Jul 2021)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:1673-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1673-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241673-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194552");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-May/018541.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Pillow' package(s) announced via the SUSE-SU-2024:1673-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-Pillow fixes the following issues:

- Fixed ImagePath.Path array handling (bsc#1194552, CVE-2022-22815, bsc#1194551, CVE-2022-22816)
- Use snprintf instead of sprintf (bsc#1188574, CVE-2021-34552)
- Fix Memory DOS in Icns, Ico and Blp Image Plugins. (bsc#1183110, CVE-2021-27921, bsc#1183108, CVE-2021-27922, bsc#1183107, CVE-2021-27923)
- Fix OOB read in SgiRleDecode.c (bsc#1183102, CVE-2021-25293)
- Use more specific regex chars to prevent ReDoS (bsc#1183101, CVE-2021-25292)
- Fix negative size read in TiffDecode.c (bsc#1183105, CVE-2021-25290)
- Raise ValueError if color specifier is too long (bsc#1190229, CVE-2021-23437)
- Incorrect error code checking in TiffDecode.c (bsc#1183103, CVE-2021-25289)
- OOB Write in TiffDecode.c (bsc#1180833, CVE-2020-35654)");

  script_tag(name:"affected", value:"'python-Pillow' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-Pillow", rpm:"python3-Pillow~7.2.0~150300.3.15.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Pillow-tk", rpm:"python3-Pillow-tk~7.2.0~150300.3.15.1", rls:"openSUSELeap15.5"))) {
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
