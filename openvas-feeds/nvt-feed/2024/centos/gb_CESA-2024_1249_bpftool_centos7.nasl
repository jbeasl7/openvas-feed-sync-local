# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884336");
  script_version("2024-08-09T05:05:42+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-26602", "CVE-2022-42896", "CVE-2023-4921", "CVE-2023-45871", "CVE-2023-38409", "CVE-2024-1086");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 01:27:19 +0000 (Mon, 28 Nov 2022)");
  script_tag(name:"creation_date", value:"2024-03-26 02:00:11 +0000 (Tue, 26 Mar 2024)");
  script_name("CentOS: Security Advisory for bpftool (CESA-2024:1249)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2024:1249");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2024-March/099235.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bpftool'
  package(s) announced via the CESA-2024:1249 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux operating system.

Security Fix(es):

  * (CVE-2024-26602, ?)

  * kernel: use-after-free in l2cap_connect and l2cap_le_connect_req in net/bluetooth/l2cap_core.c (CVE-2022-42896)

  * kernel: use-after-free in sch_qfq network scheduler (CVE-2023-4921)

  * kernel: IGB driver inadequate buffer size for frames larger than MTU (CVE-2023-45871)

  * kernel: fbcon: out-of-sync arrays in fbcon_mode_deleted due to wrong con2fb_map assignment (CVE-2023-38409)

  * kernel: nf_tables: use-after-free vulnerability in the nft_verdict_init() function (CVE-2024-1086)

For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.
Bug Fix(es):

  * [rhel-7] INFO: possible circular locking dependency detected: store+0x70/0xe0 kernfs_fop_write+0xe3/0x190 (BZ#2161654)

  * qedf: Reading /sys/kernel/debug/qedf/hostX/stop_io_on_error can cause panic (BZ#2224973)");

  script_tag(name:"affected", value:"'bpftool' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~1160.114.2.el7", rls:"CentOS7"))) {
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