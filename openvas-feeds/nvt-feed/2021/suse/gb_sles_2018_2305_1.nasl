# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2305.1");
  script_cve_id("CVE-2018-13302", "CVE-2018-1999010", "CVE-2018-1999011", "CVE-2018-1999012", "CVE-2018-1999013");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-19 20:08:19 +0000 (Wed, 19 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2305-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2305-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182305-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the SUSE-SU-2018:2305-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg fixes the following issues:
Security issues fixed:
- CVE-2018-13302: Fixed out of array access issue (bsc#1100356).
- CVE-2018-1999010: Fixed multiple out of array access vulnerabilities in
 the mms protocol that could result in accessing out of bound data via
 specially crafted input files (bnc#1102899)
- CVE-2018-1999011: Fixed a heap buffer overflow in asf_o format demuxer
 that could result in remote code execution (bnc#1102689)
- CVE-2018-1999012: Fixed an infinite loop vulnerability in pva format
 demuxer that could result in excessive amount of ressource allocation
 like CPU an RAM (CVE-2018-1999012 bnc#1102688).
- CVE-2018-1999013: Fixed an use-after-free vulnerability in the realmedia
 demuxer that could allow remote attackers to read heap memory
 (bnc#1102687)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Workstation Extension 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~4.5.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.4.2~4.5.1", rls:"SLES15.0"))) {
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
