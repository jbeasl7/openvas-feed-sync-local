# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0367.1");
  script_cve_id("CVE-2016-5009");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-14 18:00:50 +0000 (Thu, 14 Jul 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0367-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0367-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170367-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999688");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-February/002616.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the SUSE-SU-2017:0367-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ceph fixes the following issues:

* CVE-2016-5009: moncommand with empty prefix could crash monitor [bsc#987144]
* Invalid commandd in SOC7 with ceph [bsc#1008894]
* Performance fix was missing in SES4 [bsc#1005179]
* ceph build problems on ppc64le [bsc#982141]
* ceph make build unit test failure [bsc#977940]
* ceph-deploy mon create-initial fails on one node [bsc#999688]
* MDS dies while running xfstests [bsc#985232]
* Typerror while calling _recover_auth_meta() [bsc#1008501]
* OSD daemon uses ~100% CPU load right after OSD creation / first OSD start [bsc#1014338]
* civetweb HTTPS support not working [bsc#990438]
* systemd is killing off OSDs [bsc#1007216]");

  script_tag(name:"affected", value:"'ceph' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~10.2.4+git.1481215985.12b091b~16.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs1", rpm:"libcephfs1~10.2.4+git.1481215985.12b091b~16.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~10.2.4+git.1481215985.12b091b~16.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper1", rpm:"libradosstriper1~10.2.4+git.1481215985.12b091b~16.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~10.2.4+git.1481215985.12b091b~16.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cephfs", rpm:"python-cephfs~10.2.4+git.1481215985.12b091b~16.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rados", rpm:"python-rados~10.2.4+git.1481215985.12b091b~16.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rbd", rpm:"python-rbd~10.2.4+git.1481215985.12b091b~16.2", rls:"SLES12.0SP2"))) {
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
