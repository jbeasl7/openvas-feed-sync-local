# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02770.1");
  script_cve_id("CVE-2025-8176", "CVE-2025-8177");
  script_tag(name:"creation_date", value:"2025-08-14 04:12:02 +0000 (Thu, 14 Aug 2025)");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-11 16:57:45 +0000 (Thu, 11 Sep 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02770-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02770-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502770-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247106");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247108");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041172.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2025:02770-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following issues:

- Updated TIFFMergeFieldInfo() with read_count=write_count=0 for FIELD_IGNORE (bsc#1243503)
- CVE-2025-8176: Fixed heap use-after-free in tools/tiffmedian.c (bsc#1247108)
- CVE-2025-8177: Fixed possible buffer overflow in tools/thumbnail.c:setrow()
 when processing malformed TIFF files (bsc#1247106)
- Add -DCMAKE_POLICY_VERSION_MINIMUM=3.5 to fix FTBFS with cmake4
- Add %check section
- Remove Group: declarations, no longer used");

  script_tag(name:"affected", value:"'tiff' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel-32bit", rpm:"libtiff-devel-32bit~4.7.0~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.7.0~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff6-32bit", rpm:"libtiff6-32bit~4.7.0~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff6", rpm:"libtiff6~4.7.0~150600.3.13.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.7.0~150600.3.13.1", rls:"openSUSELeap15.6"))) {
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
