# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.01835.1");
  script_cve_id("CVE-2025-31162", "CVE-2025-31163", "CVE-2025-31164", "CVE-2025-46397", "CVE-2025-46398", "CVE-2025-46399", "CVE-2025-46400");
  script_tag(name:"creation_date", value:"2025-06-11 04:10:57 +0000 (Wed, 11 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-15 02:15:21 +0000 (Thu, 15 May 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:01835-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:01835-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202501835-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240380");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243263");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040187.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'transfig' package(s) announced via the SUSE-SU-2025:01835-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for transfig fixes the following issues:

Update to fig2dev version 3.2.9a

- CVE-2025-31162: Fixed a floating point exception in fig2dev in get_slope function (bsc#1240380).
- CVE-2025-31163: Fixed a segmentation fault in fig2dev in put_patternarc function (bsc#1240381).
- CVE-2025-31164: Fixed a heap buffer overflow in fig2dev in create_line_with_spline function (bsc#1240379).
- CVE-2025-46397: Fixed a stack buffer overflow in fig2dev in bezier_spline function (bsc#1243260).
- CVE-2025-46398: Fixed a stack buffer overflow in fig2dev in read_objects function (bsc#1243262).
- CVE-2025-46399: Fixed a segmentation fault in fig2dev in genge_itp_spline function (bsc#1243263).
- CVE-2025-46400: Fixed a segmentation fault in fig2dev in read_arcobject function (bsc#1243261).");

  script_tag(name:"affected", value:"'transfig' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"transfig", rpm:"transfig~3.2.9a~150600.3.5.1", rls:"openSUSELeap15.6"))) {
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
