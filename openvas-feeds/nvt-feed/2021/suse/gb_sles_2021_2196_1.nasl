# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2196.1");
  script_cve_id("CVE-2020-24370", "CVE-2020-24371");
  script_tag(name:"creation_date", value:"2021-07-01 13:05:51 +0000 (Thu, 01 Jul 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 18:12:20 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2196-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2196-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212196-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lua53' package(s) announced via the SUSE-SU-2021:2196-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lua53 fixes the following issues:

Update to version 5.3.6:

CVE-2020-24371: lgc.c mishandles the interaction between barriers and
 the sweep phase, leading to a memory access violation involving
 collectgarbage (bsc#1175449)

CVE-2020-24370: ldebug.c allows a negation overflow and segmentation
 fault in getlocal and setlocal (bsc#1175448)

Long brackets with a huge number of '=' overflow some internal buffer
 arithmetic.");

  script_tag(name:"affected", value:"'lua53' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE MicroOS 5.0.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5-32bit", rpm:"liblua5_3-5-32bit~5.3.6~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5-32bit-debuginfo", rpm:"liblua5_3-5-32bit-debuginfo~5.3.6~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5", rpm:"liblua5_3-5~5.3.6~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5-debuginfo", rpm:"liblua5_3-5-debuginfo~5.3.6~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53", rpm:"lua53~5.3.6~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-debuginfo", rpm:"lua53-debuginfo~5.3.6~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-debugsource", rpm:"lua53-debugsource~5.3.6~3.6.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-devel", rpm:"lua53-devel~5.3.6~3.6.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5-32bit", rpm:"liblua5_3-5-32bit~5.3.6~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5-32bit-debuginfo", rpm:"liblua5_3-5-32bit-debuginfo~5.3.6~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5", rpm:"liblua5_3-5~5.3.6~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5-debuginfo", rpm:"liblua5_3-5-debuginfo~5.3.6~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53", rpm:"lua53~5.3.6~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-debuginfo", rpm:"lua53-debuginfo~5.3.6~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-debugsource", rpm:"lua53-debugsource~5.3.6~3.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-devel", rpm:"lua53-devel~5.3.6~3.6.1", rls:"SLES15.0SP3"))) {
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
