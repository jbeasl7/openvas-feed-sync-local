# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833830");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2016-7069", "CVE-2017-7557", "CVE-2018-14663");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-29 14:39:30 +0000 (Tue, 29 Aug 2017)");
  script_tag(name:"creation_date", value:"2024-03-08 02:01:07 +0000 (Fri, 08 Mar 2024)");
  script_name("openSUSE: Security Advisory for dnsdist (SUSE-SU-2023:2760-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2760-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/K3MEAB5PRHIQWAYIUPXORRAFLAKTYUSL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsdist'
  package(s) announced via the SUSE-SU-2023:2760-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dnsdist fixes the following issues:

  * update to 1.8.0

  * Implements dnsdist in SLE15 (jsc#PED-3402)

  * Security fix: fixes a possible record smugging with a crafted DNS query with
      trailing data (CVE-2018-14663, bsc#1114511)

  * update to 1.2.0 (bsc#1054799, bsc#1054802) This release also addresses two
      security issues of low severity, CVE-2016-7069 and CVE-2017-7557. The first
      issue can lead to a denial of service on 32-bit if a backend sends crafted
      answers, and the second to an alteration of dnsdists ACL if the API is
      enabled, writable and an authenticated user is tricked into visiting a
      crafted website.

  ##");

  script_tag(name:"affected", value:"'dnsdist' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2", rpm:"libluajit-5_1-2~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debugsource", rpm:"dnsdist-debugsource~1.8.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit", rpm:"luajit~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-debugsource", rpm:"luajit-debugsource~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-debuginfo", rpm:"libluajit-5_1-2-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debuginfo", rpm:"dnsdist-debuginfo~1.8.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-debuginfo", rpm:"luajit-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-devel", rpm:"luajit-devel~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist", rpm:"dnsdist~1.8.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-32bit", rpm:"libluajit-5_1-2-32bit~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-32bit-debuginfo", rpm:"libluajit-5_1-2-32bit-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2", rpm:"libluajit-5_1-2~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debugsource", rpm:"dnsdist-debugsource~1.8.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit", rpm:"luajit~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-debugsource", rpm:"luajit-debugsource~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-debuginfo", rpm:"libluajit-5_1-2-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debuginfo", rpm:"dnsdist-debuginfo~1.8.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-debuginfo", rpm:"luajit-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-devel", rpm:"luajit-devel~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist", rpm:"dnsdist~1.8.0~150400.9.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-32bit", rpm:"libluajit-5_1-2-32bit~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-32bit-debuginfo", rpm:"libluajit-5_1-2-32bit-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2", rpm:"libluajit-5_1-2~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debugsource", rpm:"dnsdist-debugsource~1.8.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit", rpm:"luajit~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-debugsource", rpm:"luajit-debugsource~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-debuginfo", rpm:"libluajit-5_1-2-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debuginfo", rpm:"dnsdist-debuginfo~1.8.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-debuginfo", rpm:"luajit-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-devel", rpm:"luajit-devel~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist", rpm:"dnsdist~1.8.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-32bit", rpm:"libluajit-5_1-2-32bit~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-32bit-debuginfo", rpm:"libluajit-5_1-2-32bit-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1##", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2", rpm:"libluajit-5_1-2~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debugsource", rpm:"dnsdist-debugsource~1.8.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit", rpm:"luajit~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-debugsource", rpm:"luajit-debugsource~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-debuginfo", rpm:"libluajit-5_1-2-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist-debuginfo", rpm:"dnsdist-debuginfo~1.8.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-debuginfo", rpm:"luajit-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-devel", rpm:"luajit-devel~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsdist", rpm:"dnsdist~1.8.0~150400.9.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-32bit", rpm:"libluajit-5_1-2-32bit~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit-5_1-2-32bit-debuginfo", rpm:"libluajit-5_1-2-32bit-debuginfo~2.1.0~beta3+git.1624618403.e9577376~150400.4.2.1##", rls:"openSUSELeap15.5"))) {
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