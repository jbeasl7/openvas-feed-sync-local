# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0555.1");
  script_cve_id("CVE-2015-1142857", "CVE-2017-13215", "CVE-2017-17741", "CVE-2017-18017", "CVE-2017-18079", "CVE-2017-5715", "CVE-2018-1000004", "CVE-2018-5332", "CVE-2018-5333");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:47 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-17 15:05:59 +0000 (Wed, 17 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0555-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0555-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180555-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1045538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1054305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1059174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080579");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1081500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936530");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962257");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-February/003756.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:0555-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2017-5715: Systems with microprocessors utilizing speculative
 execution and indirect branch prediction may allow unauthorized disclosure
 of information to an attacker with local user access via a side-channel
 analysis (bnc#1068032).

 The previous fix using CPU Microcode has been complemented by building
 the Linux Kernel with return trampolines aka 'retpolines'.

- CVE-2018-5332: In the Linux kernel the rds_message_alloc_sgs() function
 did not validate a value that is used during DMA page allocation, leading
 to a heap-based out-of-bounds write (related to the rds_rdma_extra_size
 function in net/rds/rdma.c) (bnc#1075621).
- CVE-2018-5333: In the Linux kernel the rds_cmsg_atomic function in
 net/rds/rdma.c mishandled cases where page pinning fails or an invalid
 address is supplied, leading to an rds_atomic_free_op NULL pointer
 dereference (bnc#1075617).
- CVE-2017-18017: The tcpmss_mangle_packet function in
 net/netfilter/xt_TCPMSS.c in the Linux kernel allowed remote attackers
 to cause a denial of service (use-after-free and memory corruption)
 or possibly have unspecified other impact by leveraging the presence of
 xt_TCPMSS in an iptables action (bnc#1074488).
- CVE-2017-18079: drivers/input/serio/i8042.c in the Linux kernel allowed
 attackers to cause a denial of service (NULL pointer dereference and
 system crash) or possibly have unspecified other impact because the
 port->exists value can change after it is validated (bnc#1077922).
- CVE-2015-1142857: On multiple SR-IOV cars it is possible for VF's
 assigned to guests to send ethernet flow control pause frames via the
 PF. (bnc#1077355).
- CVE-2017-17741: The KVM implementation in the Linux kernel allowed
 attackers to obtain potentially sensitive information from kernel
 memory, aka a write_mmio stack-based out-of-bounds read, related to
 arch/x86/kvm/x86.c and include/trace/events/kvm.h (bnc#1073311).
- CVE-2017-13215: A elevation of privilege vulnerability in the Upstream
 kernel skcipher. (bnc#1075908).
- CVE-2018-1000004: In the Linux kernel a race condition vulnerability
 existed in the sound system, this can lead to a deadlock and denial of
 service condition (bnc#1076017).

The following non-security bugs were fixed:

- alsa: aloop: Fix inconsistent format due to incomplete rule (bsc#1045538).
- alsa: aloop: Fix racy hw constraints adjustment (bsc#1045538).
- alsa: aloop: Release cable upon open error path (bsc#1045538).
- alsa: pcm: Abort properly at pending signal in OSS read/write loops (bsc#1045538).
- alsa: pcm: Add missing error checks in OSS emulation plugin builder (bsc#1045538).
- alsa: pcm: Allow aborting mutex lock at OSS read/write loops (bsc#1045538).
- alsa: pcm: Remove incorrect snd_BUG_ON() usages (bsc#1045538).
- alsa: pcm: Remove yet ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.35.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.35.1", rls:"SLES11.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.35.1", rls:"SLES11.0SP4"))) {
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
