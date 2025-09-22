# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0930.1");
  script_cve_id("CVE-2020-1759", "CVE-2020-1760");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-13 17:46:00 +0000 (Mon, 13 Apr 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0930-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0930-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200930-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the SUSE-SU-2020:0930-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ceph fixes the following issues:

CVE-2020-1759: Fixed once reuse in msgr V2 secure mode (bsc#1166403)

CVE-2020-1760: Fixed XSS due to RGW GetObject header-splitting
 (bsc#1166484).");

  script_tag(name:"affected", value:"'ceph' package(s) on SUSE Enterprise Storage 6, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common-debuginfo", rpm:"ceph-common-debuginfo~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-debugsource", rpm:"ceph-debugsource~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs-devel", rpm:"libcephfs-devel~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2-debuginfo", rpm:"libcephfs2-debuginfo~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel", rpm:"librados-devel~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel-debuginfo", rpm:"librados-devel-debuginfo~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2-debuginfo", rpm:"librados2-debuginfo~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradospp-devel", rpm:"libradospp-devel~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd-devel", rpm:"librbd-devel~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1-debuginfo", rpm:"librbd1-debuginfo~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw-devel", rpm:"librgw-devel~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2-debuginfo", rpm:"librgw2-debuginfo~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph-argparse", rpm:"python3-ceph-argparse~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs", rpm:"python3-cephfs~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs-debuginfo", rpm:"python3-cephfs-debuginfo~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados", rpm:"python3-rados~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados-debuginfo", rpm:"python3-rados-debuginfo~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd", rpm:"python3-rbd~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd-debuginfo", rpm:"python3-rbd-debuginfo~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw", rpm:"python3-rgw~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw-debuginfo", rpm:"python3-rgw-debuginfo~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rados-objclass-devel", rpm:"rados-objclass-devel~14.2.5.389+gb0f23ac248~3.35.2", rls:"SLES15.0SP1"))) {
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
