# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833839");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-41409");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-27 03:46:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:17:17 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for pcre2 (SUSE-SU-2023:3327-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3327-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QJTQWW5R6NJPAVV4T3R7QVEGBBTCMVJR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcre2'
  package(s) announced via the SUSE-SU-2023:3327-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pcre2 fixes the following issues:

  * CVE-2022-41409: Fixed integer overflow vulnerability in pcre2test that
      allows attackers to cause a denial of service via negative input
      (bsc#1213514).

  ##");

  script_tag(name:"affected", value:"'pcre2' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"pcre2-debugsource", rpm:"pcre2-debugsource~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-devel-static", rpm:"pcre2-devel-static~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0", rpm:"libpcre2-32-0~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2", rpm:"libpcre2-posix2~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-tools-debuginfo", rpm:"pcre2-tools-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-debuginfo", rpm:"libpcre2-8-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-debuginfo", rpm:"libpcre2-posix2-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-tools", rpm:"pcre2-tools~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-devel", rpm:"pcre2-devel~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-debuginfo", rpm:"libpcre2-16-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-debuginfo", rpm:"libpcre2-32-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0", rpm:"libpcre2-16-0~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-32bit-debuginfo", rpm:"libpcre2-32-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-32bit-debuginfo", rpm:"libpcre2-16-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-32bit", rpm:"libpcre2-32-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-32bit-debuginfo", rpm:"libpcre2-8-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-32bit", rpm:"libpcre2-posix2-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-32bit", rpm:"libpcre2-16-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-32bit-debuginfo", rpm:"libpcre2-posix2-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-32bit", rpm:"libpcre2-8-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-doc", rpm:"pcre2-doc~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-64bit", rpm:"libpcre2-32-0-64bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-64bit", rpm:"libpcre2-8-0-64bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-64bit-debuginfo", rpm:"libpcre2-posix2-64bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-64bit-debuginfo", rpm:"libpcre2-32-0-64bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-64bit", rpm:"libpcre2-posix2-64bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-64bit-debuginfo", rpm:"libpcre2-16-0-64bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-64bit", rpm:"libpcre2-16-0-64bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-64bit-debuginfo", rpm:"libpcre2-8-0-64bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-debugsource", rpm:"pcre2-debugsource~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-devel-static", rpm:"pcre2-devel-static~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0", rpm:"libpcre2-32-0~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2", rpm:"libpcre2-posix2~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-tools-debuginfo", rpm:"pcre2-tools-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-debuginfo", rpm:"libpcre2-8-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-debuginfo", rpm:"libpcre2-posix2-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-tools", rpm:"pcre2-tools~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-devel", rpm:"pcre2-devel~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-debuginfo", rpm:"libpcre2-16-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-debuginfo", rpm:"libpcre2-32-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0", rpm:"libpcre2-16-0~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-32bit-debuginfo", rpm:"libpcre2-32-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-32bit-debuginfo", rpm:"libpcre2-16-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-32bit", rpm:"libpcre2-32-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-32bit-debuginfo", rpm:"libpcre2-8-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-32bit", rpm:"libpcre2-posix2-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-32bit", rpm:"libpcre2-16-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-32bit-debuginfo", rpm:"libpcre2-posix2-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-32bit", rpm:"libpcre2-8-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-doc", rpm:"pcre2-doc~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-64bit", rpm:"libpcre2-32-0-64bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-64bit", rpm:"libpcre2-8-0-64bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-64bit-debuginfo", rpm:"libpcre2-posix2-64bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-64bit-debuginfo", rpm:"libpcre2-32-0-64bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-64bit", rpm:"libpcre2-posix2-64bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-64bit-debuginfo", rpm:"libpcre2-16-0-64bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-64bit", rpm:"libpcre2-16-0-64bit~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-64bit-debuginfo", rpm:"libpcre2-8-0-64bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"pcre2-debugsource", rpm:"pcre2-debugsource~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-devel-static", rpm:"pcre2-devel-static~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0", rpm:"libpcre2-32-0~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2", rpm:"libpcre2-posix2~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-tools-debuginfo", rpm:"pcre2-tools-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-debuginfo", rpm:"libpcre2-8-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-debuginfo", rpm:"libpcre2-posix2-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-tools", rpm:"pcre2-tools~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-devel", rpm:"pcre2-devel~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-debuginfo", rpm:"libpcre2-16-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-debuginfo", rpm:"libpcre2-32-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0", rpm:"libpcre2-16-0~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-32bit-debuginfo", rpm:"libpcre2-32-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-32bit-debuginfo", rpm:"libpcre2-16-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-32bit", rpm:"libpcre2-32-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-32bit-debuginfo", rpm:"libpcre2-8-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-32bit", rpm:"libpcre2-posix2-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-32bit", rpm:"libpcre2-16-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-32bit-debuginfo", rpm:"libpcre2-posix2-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-32bit", rpm:"libpcre2-8-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-doc", rpm:"pcre2-doc~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-debugsource", rpm:"pcre2-debugsource~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-devel-static", rpm:"pcre2-devel-static~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0", rpm:"libpcre2-32-0~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2", rpm:"libpcre2-posix2~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-tools-debuginfo", rpm:"pcre2-tools-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-debuginfo", rpm:"libpcre2-8-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-debuginfo", rpm:"libpcre2-posix2-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-tools", rpm:"pcre2-tools~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-devel", rpm:"pcre2-devel~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-debuginfo", rpm:"libpcre2-16-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-debuginfo", rpm:"libpcre2-32-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0", rpm:"libpcre2-16-0~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-32bit-debuginfo", rpm:"libpcre2-32-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-32bit-debuginfo", rpm:"libpcre2-16-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-32-0-32bit", rpm:"libpcre2-32-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-32bit-debuginfo", rpm:"libpcre2-8-0-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-32bit", rpm:"libpcre2-posix2-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-16-0-32bit", rpm:"libpcre2-16-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-posix2-32bit-debuginfo", rpm:"libpcre2-posix2-32bit-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-32bit", rpm:"libpcre2-8-0-32bit~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre2-doc", rpm:"pcre2-doc~10.39~150400.4.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"pcre2-debugsource", rpm:"pcre2-debugsource~10.39~150400.4.9.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.39~150400.4.9.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-debuginfo", rpm:"libpcre2-8-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"pcre2-debugsource", rpm:"pcre2-debugsource~10.39~150400.4.9.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0", rpm:"libpcre2-8-0~10.39~150400.4.9.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre2-8-0-debuginfo", rpm:"libpcre2-8-0-debuginfo~10.39~150400.4.9.1", rls:"openSUSELeapMicro5.4"))) {
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