# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.14089.1");
  script_cve_id("CVE-2014-9710", "CVE-2018-17972", "CVE-2019-11190", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11486", "CVE-2019-11884", "CVE-2019-5489");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:23 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-20 18:10:57 +0000 (Thu, 20 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:14089-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:14089-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-201914089-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137586");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/923908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/939260");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-June/005579.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:14089-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP4 kernel version 3.0.101 was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-11477: A sequence of SACKs may have been crafted such that one can
 trigger an integer overflow, leading to a kernel panic. (bsc#1137586)

- CVE-2019-11478: It was possible to send a crafted sequence of SACKs which
 will fragment the TCP retransmission queue. An attacker may have been able to
 further exploit the fragmented queue to cause an expensive linked-list walk
 for subsequent SACKs received for that same TCP connection.

- CVE-2019-11479: It was possible to send a crafted sequence of SACKs which
 will fragment the RACK send map. A remote attacker may be able to further
 exploit the fragmented send map to cause an expensive linked-list walk for
 subsequent SACKs received for that same TCP connection. This would have
 resulted in excess resource consumption due to low mss values.

- CVE-2014-9710: The Btrfs implementation in the Linux kernel did not ensure
 that the visible xattr state is consistent with a requested replacement,
 which allowed local users to bypass intended ACL settings and gain privileges
 via standard filesystem operations (1) during an xattr-replacement time
 window, related to a race condition, or (2) after an xattr-replacement
 attempt that fails because the data did not fit (bnc#923908).

- CVE-2019-5489: The mincore() implementation in mm/mincore.c in the Linux
 kernel allowed local attackers to observe page cache access patterns of other
 processes on the same system, potentially allowing sniffing of secret
 information. (Fixing this affects the output of the fincore program.) Limited
 remote exploitation may be possible, as demonstrated by latency differences
 in accessing public files from an Apache HTTP Server (bnc#1120843).

- CVE-2019-11190: The Linux kernel allowed local users to bypass ASLR on setuid
 programs (such as /bin/su) because install_exec_creds() is called too late in
 load_elf_binary() in fs/binfmt_elf.c, and thus the ptrace_may_access() check
 has a race condition when reading /proc/pid/stat (bnc#1131543).

- CVE-2018-17972: An issue was discovered in the proc_pid_stack function in
 fs/proc/base.c in the Linux kernel It did not ensure that only root may
 inspect the kernel stack of an arbitrary task, allowing a local attacker to
 exploit racy stack unwinding and leak kernel task stack contents
 (bnc#1110785).

- CVE-2019-11884: The do_hidp_sock_ioctl function in net/bluetooth/hidp/sock.c
 in the Linux kernel allowed a local user to obtain potentially sensitive
 information from kernel stack memory via a HIDPCONNADD command, because a
 name field may not end with a '\0' character (bnc#1134848).

- CVE-2019-11486: The Siemens R3964 line discipline driver in
 drivers/tty/n_r3964.c in the Linux kernel had multiple race conditions
 (bnc#1133188).

The following ... [Please see the references for more information on the vulnerabilities]");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~108.95.2", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~108.95.2", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~108.95.2", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~108.95.2", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~108.95.2", rls:"SLES11.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem", rpm:"kernel-bigmem~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-base", rpm:"kernel-bigmem-base~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigmem-devel", rpm:"kernel-bigmem-devel~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~108.95.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~108.95.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~108.95.2", rls:"SLES11.0SP4"))) {
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
