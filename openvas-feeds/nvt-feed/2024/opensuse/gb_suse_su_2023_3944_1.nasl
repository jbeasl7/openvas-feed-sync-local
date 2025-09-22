# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833846");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-39976");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-10 16:09:41 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:34:02 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for libqb (SUSE-SU-2023:3944-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3944-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/V5G5PSHY6ZQ5SKXF44SIVVFNX6RU54B3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqb'
  package(s) announced via the SUSE-SU-2023:3944-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqb fixes the following issues:

  * CVE-2023-39976: Fixed potential bufferoverflow with long log messages
      (bsc#1214066).

  ##");

  script_tag(name:"affected", value:"'libqb' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libqb-devel", rpm:"libqb-devel~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"doxygen2man", rpm:"doxygen2man~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-tools-debuginfo", rpm:"libqb-tools-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100", rpm:"libqb100~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"doxygen2man-debuginfo", rpm:"doxygen2man-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-debugsource", rpm:"libqb-debugsource~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100-debuginfo", rpm:"libqb100-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-tests-debuginfo", rpm:"libqb-tests-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-tests", rpm:"libqb-tests~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-tools", rpm:"libqb-tools~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100-32bit-debuginfo", rpm:"libqb100-32bit-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100-32bit", rpm:"libqb100-32bit~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-devel-32bit", rpm:"libqb-devel-32bit~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100-64bit", rpm:"libqb100-64bit~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100-64bit-debuginfo", rpm:"libqb100-64bit-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-devel-64bit", rpm:"libqb-devel-64bit~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-devel", rpm:"libqb-devel~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"doxygen2man", rpm:"doxygen2man~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-tools-debuginfo", rpm:"libqb-tools-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100", rpm:"libqb100~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"doxygen2man-debuginfo", rpm:"doxygen2man-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-debugsource", rpm:"libqb-debugsource~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100-debuginfo", rpm:"libqb100-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-tests-debuginfo", rpm:"libqb-tests-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-tests", rpm:"libqb-tests~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-tools", rpm:"libqb-tools~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100-32bit-debuginfo", rpm:"libqb100-32bit-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100-32bit", rpm:"libqb100-32bit~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-devel-32bit", rpm:"libqb-devel-32bit~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100-64bit", rpm:"libqb100-64bit~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb100-64bit-debuginfo", rpm:"libqb100-64bit-debuginfo~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqb-devel-64bit", rpm:"libqb-devel-64bit~2.0.4+20211112.a2691b9~150400.4.3.1", rls:"openSUSELeap15.4"))) {
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