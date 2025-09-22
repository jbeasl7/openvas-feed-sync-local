# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1335.1");
  script_cve_id("CVE-2020-10722", "CVE-2020-10723", "CVE-2020-10724", "CVE-2020-10725", "CVE-2020-10726");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:03 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-21 01:54:28 +0000 (Thu, 21 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1335-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1335-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201335-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpdk' package(s) announced via the SUSE-SU-2020:1335-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dpdk fixes the following issues:

Security issues fixed:

CVE-2020-10722: Fixed an integer overflow in vhost_user_set_log_base()
 (bsc#1171477).

CVE-2020-10723: Fixed an integer truncation in
 vhost_user_check_and_alloc_queue_pair() (bsc#1171477).

CVE-2020-10724: Fixed a missing inputs validation in Vhost-crypto
 (bsc#1171477).

CVE-2020-10725: Fixed a segfault caused by invalid virtio descriptors
 sent from a malicious guest (bsc#1171477).

CVE-2020-10726: Fixed a denial-of-service caused by
 VHOST_USER_GET_INFLIGHT_FD message flooding (bsc#1171477).");

  script_tag(name:"affected", value:"'dpdk' package(s) on SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Module for Server Applications 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"dpdk", rpm:"dpdk~18.11.3~4.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debuginfo", rpm:"dpdk-debuginfo~18.11.3~4.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-debugsource", rpm:"dpdk-debugsource~18.11.3~4.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel", rpm:"dpdk-devel~18.11.3~4.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-devel-debuginfo", rpm:"dpdk-devel-debuginfo~18.11.3~4.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default", rpm:"dpdk-kmp-default~18.11.3_k4.12.14_197.40~4.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-kmp-default-debuginfo", rpm:"dpdk-kmp-default-debuginfo~18.11.3_k4.12.14_197.40~4.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools", rpm:"dpdk-tools~18.11.3~4.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dpdk-tools-debuginfo", rpm:"dpdk-tools-debuginfo~18.11.3~4.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-18_11", rpm:"libdpdk-18_11~18.11.3~4.6.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdpdk-18_11-debuginfo", rpm:"libdpdk-18_11-debuginfo~18.11.3~4.6.2", rls:"SLES15.0SP1"))) {
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
