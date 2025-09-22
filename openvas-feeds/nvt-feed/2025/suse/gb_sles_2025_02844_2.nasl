# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02844.2");
  script_cve_id("CVE-2022-50211", "CVE-2023-53117", "CVE-2024-53057", "CVE-2024-53164", "CVE-2025-21971", "CVE-2025-38079", "CVE-2025-38200", "CVE-2025-38213");
  script_tag(name:"creation_date", value:"2025-09-22 04:12:25 +0000 (Mon, 22 Sep 2025)");
  script_version("2025-09-22T07:08:28+0000");
  script_tag(name:"last_modification", value:"2025-09-22 07:08:28 +0000 (Mon, 22 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-22 17:55:23 +0000 (Fri, 22 Nov 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02844-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02844-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502844-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246045");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041775.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:02844-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-50211: md-raid10: fix KASAN warning (bsc#1245140).
- CVE-2023-53117: fs: prevent out-of-bounds array speculation when closing a file descriptor (bsc#1242780).
- CVE-2024-53057: net/sched: stop qdisc_tree_reduce_backlog on TC_H_ROOT (bsc#1233551).
- CVE-2024-53164: net: sched: fix ordering of qlen adjustment (bsc#1234863).
- CVE-2025-21971: net_sched: Prevent creation of classes with TC_H_ROOT (bsc#1240799).
- CVE-2025-38079: crypto: algif_hash - fix double free in hash_accept (bsc#1245217).
- CVE-2025-38200: i40e: fix MMIO write access to an invalid page in i40e_clear_hw (bsc#1246045).
- CVE-2025-38213: vgacon: Add check for vc_origin address range in vgacon_scroll() (bsc#1246037).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.189.1", rls:"SLES11.0SP4"))) {
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
