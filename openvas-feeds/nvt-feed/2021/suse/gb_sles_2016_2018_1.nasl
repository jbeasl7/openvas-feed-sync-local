# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2018.1");
  script_cve_id("CVE-2016-4470", "CVE-2016-4997", "CVE-2016-5829");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:05 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-27 15:19:49 +0000 (Mon, 27 Jun 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2018-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2018-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162018-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988498");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-August/002201.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:2018-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
- CVE-2016-5829: Multiple heap-based buffer overflows in the hiddev_ioctl_usage function in drivers/hid/usbhid/hiddev.c in the Linux kernel allowed local users to cause a denial of service or possibly have unspecified other impact via a crafted (1) HIDIOCGUSAGES or (2) HIDIOCSUSAGES ioctl call (bnc#986572).
- CVE-2016-4997: The compat IPT_SO_SET_REPLACE setsockopt implementation in the netfilter subsystem in the Linux kernel allowed local users to gain privileges or cause a denial of service (memory corruption) by leveraging in-container root access to provide a crafted offset value that triggers an unintended decrement (bnc#986362).
- CVE-2016-4470: The key_reject_and_link function in security/keys/key.c in the Linux kernel did not ensure that a certain data structure is initialized, which allowed local users to cause a denial of service (system crash) via vectors involving a crafted keyctl request2 command (bnc#984755).

The following non-security bugs were fixed:
- RDMA/cxgb4: Configure 0B MRs to match HW implementation (bsc#909589).
- RDMA/cxgb4: Do not hang threads forever waiting on WR replies (bsc#909589).
- RDMA/cxgb4: Fix locking issue in process_mpa_request (bsc#909589).
- RDMA/cxgb4: Handle NET_XMIT return codes (bsc#909589).
- RDMA/cxgb4: Increase epd buff size for debug interface (bsc#909589).
- RDMA/cxgb4: Limit MRs to less than 8GB for T4/T5 devices (bsc#909589).
- RDMA/cxgb4: Serialize CQ event upcalls with CQ destruction (bsc#909589).
- RDMA/cxgb4: Wake up waiters after flushing the qp (bsc#909589).
- bridge: superfluous skb->nfct check in br_nf_dev_queue_xmit (bsc#982544).
- iucv: call skb_linearize() when needed (bnc#979915, LTC#141240).
- kabi: prevent spurious modversion changes after bsc#982544 fix (bsc#982544).
- mm/swap.c: flush lru pvecs on compound page arrival (bnc#983721).
- mm: Fix DIF failures on ext3 filesystems (bsc#971030).
- net/qlge: Avoids recursive EEH error (bsc#954847).
- netfilter: bridge: Use __in6_dev_get rather than in6_dev_get in br_validate_ipv6 (bsc#982544).
- netfilter: bridge: do not leak skb in error paths (bsc#982544).
- netfilter: bridge: forward IPv6 fragmented packets (bsc#982544).
- qeth: delete napi struct when removing a qeth device (bnc#979915, LTC#143590).
- s390/mm: fix asce_bits handling with dynamic pagetable levels (bnc#979915, LTC#141456).
- s390/pci: fix use after free in dma_init (bnc#979915, LTC#141626).
- s390: fix test_fp_ctl inline assembly contraints (bnc#979915, LTC#143138).
- sched/cputime: Fix clock_nanosleep()/clock_gettime() inconsistency (bnc#988498).
- sched/cputime: Fix cpu_timer_sample_group() double accounting (bnc#988498).
- sched: Provide update_curr callbacks for stop/idle scheduling classes (bnc#988498).
- x86/mm/pat, /dev/mem: Remove superfluous error message (bsc#974620).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~80.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~80.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~80.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~80.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~80.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~80.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~80.1", rls:"SLES11.0SP4"))) {
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
