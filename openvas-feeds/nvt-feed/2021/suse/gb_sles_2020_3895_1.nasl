# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3895.1");
  script_cve_id("CVE-2020-27781");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:46 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-23 02:29:54 +0000 (Wed, 23 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3895-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3895-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203895-1/");
  script_xref(name:"URL", value:"https://ceph.io/releases/v15-2-8-octopus-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the SUSE-SU-2020:3895-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ceph fixes the following issues:

Security issue fixed:

CVE-2020-27781: Fixed a privilege escalation via the ceph_volume_client
 Python interface (bsc#1180155, bsc#1179802).

Non-security issues fixed:

Update to 15.2.8-80-g1f4b6229ca:
 + Rebase on tip of upstream 'octopus' branch, SHA1
 bdf3eebcd22d7d0b3dd4d5501bee5bac354d5b55
 * upstream Octopus v15.2.8 release, see
 [link moved to references]

Update to 15.2.7-776-g343cd10fe5:
 + Rebase on tip of upstream 'octopus' branch, SHA1
 1b8a634fdcd94dfb3ba650793fb1b6d09af65e05
 * (bsc#1178860) mgr/dashboard: Disable TLS 1.0 and 1.1
 + (bsc#1179016) rpm: require smartmontools on SUSE
 + (bsc#1180107) ceph-volume: pass --filter-for-batch from drive-group
 subcommand");

  script_tag(name:"affected", value:"'ceph' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise Module for Basesystem 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common-debuginfo", rpm:"ceph-common-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-debugsource", rpm:"ceph-debugsource~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs-devel", rpm:"libcephfs-devel~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2-debuginfo", rpm:"libcephfs2-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel", rpm:"librados-devel~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel-debuginfo", rpm:"librados-devel-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2-debuginfo", rpm:"librados2-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradospp-devel", rpm:"libradospp-devel~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd-devel", rpm:"librbd-devel~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1-debuginfo", rpm:"librbd1-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw-devel", rpm:"librgw-devel~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2-debuginfo", rpm:"librgw2-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph-argparse", rpm:"python3-ceph-argparse~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph-common", rpm:"python3-ceph-common~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs", rpm:"python3-cephfs~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs-debuginfo", rpm:"python3-cephfs-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados", rpm:"python3-rados~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados-debuginfo", rpm:"python3-rados-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd", rpm:"python3-rbd~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd-debuginfo", rpm:"python3-rbd-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw", rpm:"python3-rgw~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw-debuginfo", rpm:"python3-rgw-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rados-objclass-devel", rpm:"rados-objclass-devel~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-nbd", rpm:"rbd-nbd~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rbd-nbd-debuginfo", rpm:"rbd-nbd-debuginfo~15.2.8.80+g1f4b6229ca~3.13.1", rls:"SLES15.0SP2"))) {
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
