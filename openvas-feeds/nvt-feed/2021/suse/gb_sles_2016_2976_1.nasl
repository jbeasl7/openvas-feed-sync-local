# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2976.1");
  script_cve_id("CVE-2013-4312", "CVE-2015-7513", "CVE-2015-8956", "CVE-2016-0823", "CVE-2016-3841", "CVE-2016-4997", "CVE-2016-5696", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7042", "CVE-2016-7097", "CVE-2016-7117", "CVE-2016-7425");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:03 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-11 23:33:01 +0000 (Tue, 11 Oct 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2976-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2976-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162976-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1000189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1001419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1004520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1005903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/763198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/771065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/799133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/803320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/839104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/843236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/860441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/865783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/911687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/967716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/968014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971975");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/973203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/976867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/977687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/982783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991665");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/992566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/993891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994618");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/995968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996329");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/996664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/998689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/999932");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-December/002439.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:2976-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel was updated to receive various security and bugfixes.

For the PowerPC64 a new 'bigmem' flavor has been added to support big Power machines. (FATE#319026)

The following security bugs were fixed:

- CVE-2016-7042: The proc_keys_show function in security/keys/proc.c in the Linux kernel, when the GNU Compiler Collection (gcc) stack protector is enabled, uses an incorrect buffer size for certain timeout data, which allowed local users to cause a denial of service (stack memory corruption and panic) by reading the /proc/keys file (bnc#1004517).
- CVE-2016-7097: The filesystem implementation in the Linux kernel preserves the setgid bit during a setxattr call, which allowed local users to gain group privileges by leveraging the existence of a setgid program with restrictions on execute permissions (bnc#995968).
- CVE-2015-8956: The rfcomm_sock_bind function in net/bluetooth/rfcomm/sock.c in the Linux kernel allowed local users to obtain sensitive information or cause a denial of service (NULL pointer dereference) via vectors involving a bind system call on a Bluetooth RFCOMM socket (bnc#1003925).
- CVE-2016-7117: Use-after-free vulnerability in the __sys_recvmmsg function in net/socket.c in the Linux kernel allowed remote attackers to execute arbitrary code via vectors involving a recvmmsg system call that is mishandled during error processing (bnc#1003077).
- CVE-2016-0823: The pagemap_open function in fs/proc/task_mmu.c in the Linux kernel allowed local users to obtain sensitive physical-address information by reading a pagemap file, aka Android internal bug 25739721 (bnc#994759).
- CVE-2016-7425: The arcmsr_iop_message_xfer function in drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did not restrict a certain length field, which allowed local users to gain privileges or cause a denial of service (heap-based buffer overflow) via an ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).
- CVE-2016-3841: The IPv6 stack in the Linux kernel mishandled options data, which allowed local users to gain privileges or cause a denial of service (use-after-free and system crash) via a crafted sendmsg system call (bnc#992566).
- CVE-2016-6828: The tcp_check_send_head function in include/net/tcp.h in the Linux kernel did not properly maintain certain SACK state after a failed data copy, which allowed local users to cause a denial of service (tcp_xmit_retransmit_queue use-after-free and system crash) via a crafted SACK option (bnc#994296).
- CVE-2016-5696: net/ipv4/tcp_input.c in the Linux kernel did not properly determine the rate of challenge ACK segments, which made it easier for remote attackers to hijack TCP sessions via a blind in-window attack (bnc#989152).
- CVE-2016-6480: Race condition in the ioctl_send_fib function in drivers/scsi/aacraid/commctrl.c in the Linux kernel allowed local users to cause a denial of service (out-of-bounds ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~88.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~88.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~88.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~88.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~88.1", rls:"SLES11.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~88.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~88.1", rls:"SLES11.0SP4"))) {
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
