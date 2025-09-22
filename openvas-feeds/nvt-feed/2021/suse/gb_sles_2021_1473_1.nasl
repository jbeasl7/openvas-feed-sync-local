# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1473.1");
  script_cve_id("CVE-2020-25678", "CVE-2020-27839", "CVE-2021-20288");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-22 17:31:37 +0000 (Thu, 22 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1473-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1473-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211473-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1145463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183074");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183487");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-May/008721.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the SUSE-SU-2021:1473-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ceph fixes the following issues:

- ceph was updated to 14.2.20-402-g6aa76c6815:
 * CVE-2021-20288: Fixed unauthorized global_id reuse (bsc#1183074).
 * CVE-2020-25678: Do not add sensitive information in Ceph log files (bsc#1178905).
 * CVE-2020-27839: Use secure cookies to store JWT Token (bsc#1179997).
 * mgr/dashboard: prometheus alerting: add some leeway for package drops and errors (bsc#1145463)
 * mon: have 'mon stat' output json as well (bsc#1174466)
 * rpm: ceph-mgr-dashboard recommends python3-saml on SUSE (bsc#1177200)
 * mgr/dashboard: Display a warning message in Dashboard when debug mode is enabled (bsc#1178235)
 * rgw: cls/user: set from_index for reset stats calls (bsc#1178837)
 * mgr/dashboard: Disable TLS 1.0 and 1.1 (bsc#1178860)
 * bluestore: provide a different name for fallback allocator (bsc#1180118)
 * test/run-cli-tests: use cram from github (bsc#1181378)
 * mgr/dashboard: fix 'Python2 Cookie module import fails on Python3' (bsc#1183487)
 * common: make ms_bind_msgr2 default to 'false' (bsc#1180594)");

  script_tag(name:"affected", value:"'ceph' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs-devel", rpm:"libcephfs-devel~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados-devel", rpm:"librados-devel~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradospp-devel", rpm:"libradospp-devel~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd-devel", rpm:"librbd-devel~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw-devel", rpm:"librgw-devel~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph-argparse", rpm:"python3-ceph-argparse~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cephfs", rpm:"python3-cephfs~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados", rpm:"python3-rados~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd", rpm:"python3-rbd~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw", rpm:"python3-rgw~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rados-objclass-devel", rpm:"rados-objclass-devel~14.2.20.402+g6aa76c6815~3.60.1", rls:"SLES15.0SP1"))) {
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
