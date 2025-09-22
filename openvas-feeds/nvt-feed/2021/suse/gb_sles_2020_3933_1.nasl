# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3933.1");
  script_cve_id("CVE-2020-0487", "CVE-2020-0499");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-05 16:42:53 +0000 (Tue, 05 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3933-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3933-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203933-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180112");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-December/008120.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flac' package(s) announced via the SUSE-SU-2020:3933-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for flac fixes the following issues:

- CVE-2020-0487: Fixed a memory leak (bsc#1180112).
- CVE-2020-0499: Fixed an out-of-bounds access (bsc#1180099).");

  script_tag(name:"affected", value:"'flac' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"flac-debuginfo", rpm:"flac-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flac-debugsource", rpm:"flac-debugsource~1.3.2~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flac-devel", rpm:"flac-devel~1.3.2~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC++6", rpm:"libFLAC++6~1.3.2~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC++6-debuginfo", rpm:"libFLAC++6-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8", rpm:"libFLAC8~1.3.2~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-debuginfo", rpm:"libFLAC8-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flac", rpm:"flac~1.3.2~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-32bit", rpm:"libFLAC8-32bit~1.3.2~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-32bit-debuginfo", rpm:"libFLAC8-32bit-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"flac-debuginfo", rpm:"flac-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flac-debugsource", rpm:"flac-debugsource~1.3.2~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flac-devel", rpm:"flac-devel~1.3.2~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC++6", rpm:"libFLAC++6~1.3.2~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC++6-debuginfo", rpm:"libFLAC++6-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8", rpm:"libFLAC8~1.3.2~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-debuginfo", rpm:"libFLAC8-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flac", rpm:"flac~1.3.2~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-32bit", rpm:"libFLAC8-32bit~1.3.2~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-32bit-debuginfo", rpm:"libFLAC8-32bit-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"flac-debuginfo", rpm:"flac-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flac-debugsource", rpm:"flac-debugsource~1.3.2~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flac-devel", rpm:"flac-devel~1.3.2~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC++6", rpm:"libFLAC++6~1.3.2~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC++6-debuginfo", rpm:"libFLAC++6-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8", rpm:"libFLAC8~1.3.2~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-debuginfo", rpm:"libFLAC8-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flac", rpm:"flac~1.3.2~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-32bit", rpm:"libFLAC8-32bit~1.3.2~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-32bit-debuginfo", rpm:"libFLAC8-32bit-debuginfo~1.3.2~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"flac-devel", rpm:"flac-devel~1.3.2~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC++6", rpm:"libFLAC++6~1.3.2~3.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8", rpm:"libFLAC8~1.3.2~3.6.1", rls:"SLES15.0"))) {
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
