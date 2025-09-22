# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833237");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-45853");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-19 12:44:29 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:53:05 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for zlib (SUSE-SU-2023:4215-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4215-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/THZ5CUZ3AVVUFD2GXLOZ5EBT3HOHXHQF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zlib'
  package(s) announced via the SUSE-SU-2023:4215-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for zlib fixes the following issues:

  * CVE-2023-45853: Fixed an integer overflow that would lead to a buffer
      overflow in the minizip subcomponent (bsc#1216378).

  ##");

  script_tag(name:"affected", value:"'zlib' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libminizip1", rpm:"libminizip1~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-debuginfo", rpm:"libz1-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-static", rpm:"zlib-devel-static~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1", rpm:"libz1~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel", rpm:"zlib-devel~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-testsuite-debuginfo", rpm:"zlib-testsuite-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minizip-devel", rpm:"minizip-devel~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-testsuite", rpm:"zlib-testsuite~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-debuginfo", rpm:"libminizip1-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-debugsource", rpm:"zlib-debugsource~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-32bit-debuginfo", rpm:"libminizip1-32bit-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-32bit-debuginfo", rpm:"libz1-32bit-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-32bit", rpm:"zlib-devel-32bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-static-32bit", rpm:"zlib-devel-static-32bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-32bit", rpm:"libminizip1-32bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-32bit", rpm:"libz1-32bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-64bit-debuginfo", rpm:"libz1-64bit-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-64bit", rpm:"zlib-devel-64bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-64bit", rpm:"libminizip1-64bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-64bit-debuginfo", rpm:"libminizip1-64bit-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-static-64bit", rpm:"zlib-devel-static-64bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-64bit", rpm:"libz1-64bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1", rpm:"libminizip1~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-debuginfo", rpm:"libz1-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-static", rpm:"zlib-devel-static~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1", rpm:"libz1~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel", rpm:"zlib-devel~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-testsuite-debuginfo", rpm:"zlib-testsuite-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"minizip-devel", rpm:"minizip-devel~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-testsuite", rpm:"zlib-testsuite~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-debuginfo", rpm:"libminizip1-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-debugsource", rpm:"zlib-debugsource~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-32bit-debuginfo", rpm:"libminizip1-32bit-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-32bit-debuginfo", rpm:"libz1-32bit-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-32bit", rpm:"zlib-devel-32bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-static-32bit", rpm:"zlib-devel-static-32bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-32bit", rpm:"libminizip1-32bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-32bit", rpm:"libz1-32bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-64bit-debuginfo", rpm:"libz1-64bit-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-64bit", rpm:"zlib-devel-64bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-64bit", rpm:"libminizip1-64bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminizip1-64bit-debuginfo", rpm:"libminizip1-64bit-debuginfo~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zlib-devel-static-64bit", rpm:"zlib-devel-static-64bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libz1-64bit", rpm:"libz1-64bit~1.2.13~150500.4.3.1", rls:"openSUSELeap15.5"))) {
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