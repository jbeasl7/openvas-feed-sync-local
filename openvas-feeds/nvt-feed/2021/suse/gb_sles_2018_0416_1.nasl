# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0416.1");
  script_cve_id("CVE-2017-15129", "CVE-2017-17712", "CVE-2017-17862", "CVE-2017-17864", "CVE-2017-18017", "CVE-2017-5715", "CVE-2018-1000004", "CVE-2018-5332", "CVE-2018-5333");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-17 15:05:59 +0000 (Wed, 17 Jan 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0416-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0416-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180416-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1038085");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1043652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1048585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077068");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988524");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-February/003721.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:0416-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.114 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2017-5715: Systems with microprocessors utilizing speculative execution and indirect branch prediction may allow unauthorized disclosure of information to an attacker with local user access via a side-channel analysis (bnc#1068032).

 The previous fix using CPU Microcode has been complemented by building the Linux Kernel with return trampolines aka 'retpolines'.

- CVE-2017-15129: A use-after-free vulnerability was found in network namespaces code affecting the Linux kernel The function get_net_ns_by_id() in net/core/net_namespace.c did not check for the net::count value after it has found a peer network in netns_ids idr, which could lead to double free and memory corruption. This vulnerability could allow an unprivileged local user to induce kernel memory corruption on the system, leading to a crash. Due to the nature of the flaw, privilege escalation cannot be fully ruled out, although it is thought to be unlikely (bnc#1074839).
- CVE-2017-17712: The raw_sendmsg() function in net/ipv4/raw.c in the Linux kernel has a race condition in inet->hdrincl that leads to uninitialized stack pointer usage, this allowed a local user to execute code and gain privileges (bnc#1073229).
- CVE-2017-17862: kernel/bpf/verifier.c in the Linux kernel ignored unreachable code, even though it would still be processed by JIT compilers. This behavior, also considered an improper branch-pruning logic issue, could possibly be used by local users for denial of service (bnc#1073928).
- CVE-2017-17864: kernel/bpf/verifier.c in the Linux kernel mishandled states_equal comparisons between the pointer data type and the UNKNOWN_VALUE data type, which allowed local users to obtain potentially sensitive address information, aka a 'pointer leak (bnc#1073928).
- CVE-2017-18017: The tcpmss_mangle_packet function in net/netfilter/xt_TCPMSS.c in the Linux kernel allowed remote attackers to cause a denial of service (use-after-free and memory corruption) or possibly have unspecified other impact by leveraging the presence of xt_TCPMSS in an iptables action (bnc#1074488).
- CVE-2018-1000004: In the Linux kernel a race condition vulnerability existed in the sound system, this can lead to a deadlock and denial of service condition (bnc#1076017).
- CVE-2018-5332: In the Linux kernel the rds_message_alloc_sgs() function did not validate a value that is used during DMA page allocation, leading to a heap-based out-of-bounds write (related to the rds_rdma_extra_size function in net/rds/rdma.c) (bnc#1075621).
- CVE-2018-5333: In the Linux kernel the rds_cmsg_atomic function in net/rds/rdma.c mishandled cases where page pinning fails or an invalid address is supplied, leading to an rds_atomic_free_op NULL pointer dereference (bnc#1075617).

The following non-security ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.114~92.64.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.114~92.64.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.114~92.64.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.114~92.64.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.114~92.64.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.114~92.64.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.114~92.64.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.114~92.64.1", rls:"SLES12.0SP2"))) {
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
