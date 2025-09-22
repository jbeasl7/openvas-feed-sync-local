# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0143.1");
  script_cve_id("CVE-2019-2126", "CVE-2019-9232", "CVE-2019-9325", "CVE-2019-9371", "CVE-2019-9433");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-22 19:16:42 +0000 (Thu, 22 Aug 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0143-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0143-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200143-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160615");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-January/006387.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvpx' package(s) announced via the SUSE-SU-2020:0143-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libvpx fixes the following issues:

- CVE-2019-2126: Fixed a double free in ParseContentEncodingEntry() (bsc#1160611).
- CVE-2019-9325: Fixed an out-of-bounds read (bsc#1160612).
- CVE-2019-9232: Fixed an out-of-bounds memory access on fuzzed data (bsc#1160613).
- CVE-2019-9433: Fixed a use-after-free in vp8_deblock() (bsc#1160614).
- CVE-2019-9371: Fixed a resource exhaustion after memory leak (bsc#1160615).");

  script_tag(name:"affected", value:"'libvpx' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"libvpx-debugsource", rpm:"libvpx-debugsource~1.6.1~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx4", rpm:"libvpx4~1.6.1~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx4-debuginfo", rpm:"libvpx4-debuginfo~1.6.1~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-devel", rpm:"libvpx-devel~1.6.1~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vpx-tools", rpm:"vpx-tools~1.6.1~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vpx-tools-debuginfo", rpm:"vpx-tools-debuginfo~1.6.1~6.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libvpx-debugsource", rpm:"libvpx-debugsource~1.6.1~6.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx4", rpm:"libvpx4~1.6.1~6.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx4-debuginfo", rpm:"libvpx4-debuginfo~1.6.1~6.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-devel", rpm:"libvpx-devel~1.6.1~6.3.1", rls:"SLES15.0SP1"))) {
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
