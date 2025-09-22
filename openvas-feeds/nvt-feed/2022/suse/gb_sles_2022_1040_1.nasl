# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1040.1");
  script_cve_id("CVE-2021-22570");
  script_tag(name:"creation_date", value:"2022-03-31 04:11:26 +0000 (Thu, 31 Mar 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-09 18:00:08 +0000 (Fri, 09 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1040-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1040-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221040-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'protobuf' package(s) announced via the SUSE-SU-2022:1040-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for protobuf fixes the following issues:

CVE-2021-22570: Fix incorrect parsing of nullchar in the proto symbol
 (bsc#1195258).");

  script_tag(name:"affected", value:"'protobuf' package(s) on SUSE Linux Enterprise Installer 15-SP2, SUSE Linux Enterprise Micro 5.0, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Module for Public Cloud 15-SP2, SUSE Linux Enterprise Module for Public Cloud 15-SP3, SUSE Linux Enterprise Module for Public Cloud 15-SP4, SUSE Linux Enterprise Module for SUSE Manager Server 4.1, SUSE Linux Enterprise Module for SUSE Manager Server 4.2, SUSE Linux Enterprise Realtime Extension 15-SP2.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite20", rpm:"libprotobuf-lite20~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf20", rpm:"libprotobuf20~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf20-debuginfo", rpm:"libprotobuf20-debuginfo~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-debugsource", rpm:"protobuf-debugsource~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite20-debuginfo", rpm:"libprotobuf-lite20-debuginfo~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc20", rpm:"libprotoc20~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc20-debuginfo", rpm:"libprotoc20-debuginfo~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel", rpm:"protobuf-devel~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel-debuginfo", rpm:"protobuf-devel-debuginfo~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-protobuf", rpm:"python2-protobuf~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-protobuf", rpm:"python3-protobuf~3.9.2~4.12.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite20", rpm:"libprotobuf-lite20~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite20-debuginfo", rpm:"libprotobuf-lite20-debuginfo~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf20", rpm:"libprotobuf20~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf20-debuginfo", rpm:"libprotobuf20-debuginfo~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-debugsource", rpm:"protobuf-debugsource~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc20", rpm:"libprotoc20~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc20-debuginfo", rpm:"libprotoc20-debuginfo~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel", rpm:"protobuf-devel~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel-debuginfo", rpm:"protobuf-devel-debuginfo~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-protobuf", rpm:"python2-protobuf~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-protobuf", rpm:"python3-protobuf~3.9.2~4.12.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python3-protobuf", rpm:"python3-protobuf~3.9.2~4.12.1", rls:"SLES15.0SP2"))) {
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
