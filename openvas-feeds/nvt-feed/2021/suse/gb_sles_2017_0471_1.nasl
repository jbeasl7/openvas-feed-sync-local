# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0471.1");
  script_cve_id("CVE-2014-9904", "CVE-2015-8956", "CVE-2015-8962", "CVE-2015-8963", "CVE-2015-8964", "CVE-2016-10088", "CVE-2016-4470", "CVE-2016-4997", "CVE-2016-5696", "CVE-2016-5828", "CVE-2016-5829", "CVE-2016-6130", "CVE-2016-6327", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7425", "CVE-2016-7910", "CVE-2016-7911", "CVE-2016-7913", "CVE-2016-7914", "CVE-2016-8399", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-8658", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9576", "CVE-2016-9756", "CVE-2016-9793", "CVE-2016-9806", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5551");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-09 19:11:13 +0000 (Thu, 09 Feb 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0471-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0471-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170471-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008833");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1008979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1009969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1016482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1017710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019300");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/881008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/958606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/961257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/990384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999943");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-February/002647.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:0471-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 GA LTSS kernel was updated to 3.12.61 to receive various security and bugfixes.

The following feature was implemented:

- The ext2 filesystem got re-enabled and supported to allow support for 'XIP' (Execute In Place) (FATE#320805).


The following security bugs were fixed:

- CVE-2017-5551: The tmpfs filesystem implementation in the Linux kernel preserved the setgid bit during a setxattr call, which allowed local users to gain group privileges by leveraging the existence of a setgid program with restrictions on execute permissions (bsc#1021258).
- CVE-2016-7097: The filesystem implementation in the Linux kernel preserved the setgid bit during a setxattr call, which allowed local users to gain group privileges by leveraging the existence of a setgid program with restrictions on execute permissions (bnc#995968).
- CVE-2017-2583: A Linux kernel built with the Kernel-based Virtual Machine (CONFIG_KVM) support was vulnerable to an incorrect segment selector(SS) value error. A user/process inside guest could have used this flaw to crash the guest resulting in DoS or potentially escalate their privileges inside guest. (bsc#1020602).
- CVE-2017-2584: arch/x86/kvm/emulate.c in the Linux kernel allowed local users to obtain sensitive information from kernel memory or cause a denial of service (use-after-free) via a crafted application that leverages instruction emulation for fxrstor, fxsave, sgdt, and sidt (bnc#1019851).
- CVE-2016-10088: The sg implementation in the Linux kernel did not properly restrict write operations in situations where the KERNEL_DS option is set, which allowed local users to read or write to arbitrary kernel memory locations or cause a denial of service (use-after-free) by leveraging access to a /dev/sg device, related to block/bsg.c and drivers/scsi/sg.c. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-9576 (bnc#1017710).
- CVE-2016-8645: The TCP stack in the Linux kernel mishandled skb truncation, which allowed local users to cause a denial of service (system crash) via a crafted application that made sendto system calls, related to net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c (bnc#1009969).
- CVE-2016-8399: An elevation of privilege vulnerability in the kernel networking subsystem could enable a local malicious application to execute arbitrary code within the context of the kernel. This issue is rated as Moderate because it first requires compromising a privileged process and current compiler optimizations restrict access to the vulnerable code. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID: A-31349935 (bnc#1014746).
- CVE-2016-9806: Race condition in the netlink_dump function in net/netlink/af_netlink.c in the Linux kernel allowed local users to cause a denial of service (double free) or possibly have unspecified other impact via a crafted application that made sendmsg system ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.61~52.66.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_66-default", rpm:"kgraft-patch-3_12_61-52_66-default~1~2.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_66-xen", rpm:"kgraft-patch-3_12_61-52_66-xen~1~2.1", rls:"SLES12.0"))) {
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
