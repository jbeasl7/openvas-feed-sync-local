# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1417.1");
  script_cve_id("CVE-2017-16818", "CVE-2018-7262");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-18 18:36:26 +0000 (Wed, 18 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1417-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1417-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181417-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081379");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087493");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-May/004086.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the SUSE-SU-2018:1417-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ceph fixes the following issues:

Security issues fixed:

- CVE-2018-7262: rgw: malformed http headers can crash rgw (bsc#1081379).
- CVE-2017-16818: User reachable asserts allow for DoS (bsc#1063014).

Bug fixes:

- bsc#1061461: OSDs keep generating coredumps after adding new OSD node to cluster.
- bsc#1079076: RGW openssl fixes.
- bsc#1067088: Upgrade to SES5 restarted all nodes, majority of OSDs aborts during start.
- bsc#1056125: Some OSDs are down when doing performance testing on rbd image in EC Pool.
- bsc#1087269: allow_ec_overwrites option not in command options list.
- bsc#1051598: Fix mountpoint check for systemctl enable --runtime.
- bsc#1070357: Zabbix mgr module doesn't recover from HEALTH_ERR.
- bsc#1066502: After upgrading a single OSD from SES 4 to SES 5 the OSDs do not rejoin the cluster.
- bsc#1067119: Crushtool decompile creates wrong device entries (device 20 device20) for not existing / deleted OSDs.
- bsc#1060904: Loglevel misleading during keystone authentication.
- bsc#1056967: Monitors goes down after pool creation on cluster with 120 OSDs.
- bsc#1067705: Issues with RGW Multi-Site Federation between SES5 and RH Ceph Storage 2.
- bsc#1059458: Stopping / restarting rados gateway as part of deepsea stage.4 executions causes core-dump of radosgw.
- bsc#1087493: Commvault cannot reconnect to storage after restarting haproxy.
- bsc#1066182: Container synchronization between two Ceph clusters failed.
- bsc#1081600: Crash in civetweb/RGW.
- bsc#1054061: NFS-GANESHA service failing while trying to list mountpoint on client.
- bsc#1074301: OSDs keep aborting: SnapMapper failed asserts.
- bsc#1086340: XFS metadata corruption on rbd-nbd mapped image with journaling feature enabled.
- bsc#1080788: fsid mismatch when creating additional OSDs.
- bsc#1071386: Metadata spill onto block.slow.");

  script_tag(name:"affected", value:"'ceph' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~12.2.5+git.1524775272.5e7ea8cf03~2.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~12.2.5+git.1524775272.5e7ea8cf03~2.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~12.2.5+git.1524775272.5e7ea8cf03~2.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper1", rpm:"libradosstriper1~12.2.5+git.1524775272.5e7ea8cf03~2.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~12.2.5+git.1524775272.5e7ea8cf03~2.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~12.2.5+git.1524775272.5e7ea8cf03~2.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cephfs", rpm:"python-cephfs~12.2.5+git.1524775272.5e7ea8cf03~2.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rados", rpm:"python-rados~12.2.5+git.1524775272.5e7ea8cf03~2.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rbd", rpm:"python-rbd~12.2.5+git.1524775272.5e7ea8cf03~2.7.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rgw", rpm:"python-rgw~12.2.5+git.1524775272.5e7ea8cf03~2.7.1", rls:"SLES12.0SP3"))) {
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
