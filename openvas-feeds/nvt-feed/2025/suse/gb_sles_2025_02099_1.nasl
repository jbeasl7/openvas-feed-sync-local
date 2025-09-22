# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02099.1");
  script_cve_id("CVE-2017-5753", "CVE-2023-2162", "CVE-2023-3567", "CVE-2023-52973", "CVE-2023-52974", "CVE-2023-53000", "CVE-2024-53141", "CVE-2025-21700", "CVE-2025-21702", "CVE-2025-22004");
  script_tag(name:"creation_date", value:"2025-06-27 04:13:03 +0000 (Fri, 27 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-10 19:25:08 +0000 (Tue, 10 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02099-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02099-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502099-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240835");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040464.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:02099-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-53141: netfilter: ipset: add missing range check in bitmap_ip_uadt (bsc#1234381).
- CVE-2025-21700: net: sched: Disallow replacing of child qdisc from one parent to another (bsc#1237159).
- CVE-2025-21702: pfifo_tail_enqueue: Drop new packet when sch->limit == 0 (bsc#1237312).
- CVE-2025-22004: net: atm: fix use after free in lec_send() (bsc#1240835).

The following non-security bugs were fixed:

- mtd: phram: Add the kernel lock down check (bsc#1232649).
- net_sched: sch_fifo: implement lockless __fifo_dump() (bsc#1237312)
- netfilter: ipset: Check and reject crazy /0 input parameters (git-fixes)
- netfilter: ipset: Fix overflow before widen in the bitmap_ip_create() function (git-fixes)");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.183.1", rls:"SLES11.0SP4"))) {
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
