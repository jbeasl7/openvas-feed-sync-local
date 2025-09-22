# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2736.1");
  script_cve_id("CVE-2019-10222");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:15 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-13 20:09:33 +0000 (Wed, 13 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2736-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2736-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192736-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph, ceph-iscsi, ses-manual_en' package(s) announced via the SUSE-SU-2019:2736-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ceph, ceph-iscsi and ses-manual_en fixes the following issues:

Security issues fixed:
CVE-2019-10222: Fixed RGW crash caused by unauthenticated clients.
 (bsc#1145093)

Non-security issues-fixed:
ceph-volume: prints errors to stdout with --format json (bsc#1132767)

mgr/dashboard: Changing rgw-api-host does not get effective without
 disable/enable dashboard mgr module (bsc#1137503)

mgr/dashboard: Silence Alertmanager alerts (bsc#1141174)

mgr/dashboard: Fix e2e failures caused by webdriver version (bsc#1145759)

librbd: always try to acquire exclusive lock when removing image
 (bsc#1149093)

The no{up,down,in,out} related commands have been revamped (bsc#1151990)

radosgw-admin gets two new subcommands for managing expire-stale
 objects. (bsc#1151991)

Deploying a single new BlueStore OSD on a cluster upgraded to SES6 from
 SES5 breaks pool utilization stats reported by ceph df (bsc#1151992)

Ceph cluster will no longer issue a health warning if CRUSH tunables are
 older than 'hammer' (bsc#1151993)

Nautilus-based librbd clients can not open images on Jewel clusters
 (bsc#1151994)

The RGW num_rados_handles has been removed in Ceph 14.2.3 (bsc#1151995)

'osd_deep_scrub_large_omap_object_key_threshold' has been lowered in
 Nautilus 14.2.3 (bsc#1152002)

Support iSCSI target-level CHAP authentication (bsc#1145617)

Validation and render of iSCSI controls based 'type' (bsc#1140491)

Fix error editing iSCSI image advanced settings (bsc#1146656)

Fix error during iSCSI target edit

Fixes in ses-manual_en:
Added a new chapter with changelogs of Ceph releases. (bsc#1135584)

Rewrote rolling updates and replaced running stage.0 with manual
 commands to prevent infinite loop. (bsc#1134444)

Improved name of CaaSP to its fuller version. (bsc#1151439)

Verify which OSD's are going to be removed before running stage.5.
 (bsc#1150406)

Added two additional steps to recovering an OSD. (bsc#1147132)

Fixes in ceph-iscsi:
Validate kernel LIO controls type and value (bsc#1140491)

TPG lun_id persistence (bsc#1145618)

Target level CHAP authentication (bsc#1145617)

ceph-iscsi was updated to the upstream 3.2 release:
Always use host FQDN instead of shortname

Validate min/max value for target controls and rbd:user/tcmu-runner
 image controls (bsc#1140491)");

  script_tag(name:"affected", value:"'ceph, ceph-iscsi, ses-manual_en' package(s) on SUSE Enterprise Storage 6, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common-debuginfo", rpm:"ceph-common-debuginfo~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-debugsource", rpm:"ceph-debugsource~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs-devel", rpm:"libcephfs-devel~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2-debuginfo", rpm:"libcephfs2-debuginfo~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel", rpm:"librados-devel~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel-debuginfo", rpm:"librados-devel-debuginfo~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2-debuginfo", rpm:"librados2-debuginfo~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradospp-devel", rpm:"libradospp-devel~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd-devel", rpm:"librbd-devel~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1-debuginfo", rpm:"librbd1-debuginfo~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw-devel", rpm:"librgw-devel~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2-debuginfo", rpm:"librgw2-debuginfo~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph-argparse", rpm:"python3-ceph-argparse~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs", rpm:"python3-cephfs~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs-debuginfo", rpm:"python3-cephfs-debuginfo~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados", rpm:"python3-rados~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados-debuginfo", rpm:"python3-rados-debuginfo~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd", rpm:"python3-rbd~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd-debuginfo", rpm:"python3-rbd-debuginfo~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw", rpm:"python3-rgw~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw-debuginfo", rpm:"python3-rgw-debuginfo~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rados-objclass-devel", rpm:"rados-objclass-devel~14.2.4.373+gc3e67ed133~3.19.1", rls:"SLES15.0SP1"))) {
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
