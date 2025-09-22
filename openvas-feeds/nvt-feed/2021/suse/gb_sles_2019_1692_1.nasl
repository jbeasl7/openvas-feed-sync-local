# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1692.1");
  script_cve_id("CVE-2018-17972", "CVE-2019-11190", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-3846", "CVE-2019-5489");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-04 19:53:50 +0000 (Tue, 04 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1692-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1692-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191692-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1132472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137586");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-June/005630.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1692-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel version 3.12.61 was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-11477: A sequence of SACKs may have been crafted by a remote
 attacker such that one can trigger an integer overflow, leading to a kernel
 panic. (bsc#1137586).

- CVE-2019-11478: It was possible to send a crafted sequence of SACKs which
 would fragment the TCP retransmission queue. A remote attacker may have been
 able to further exploit the fragmented queue to cause an expensive linked-list
 walk for subsequent SACKs received for that same TCP connection.

- CVE-2019-11479: It was possible to send a crafted sequence of SACKs which
 would fragment the RACK send map. A remote attacker may have been able to further
 exploit the fragmented send map to cause an expensive linked-list walk for
 subsequent SACKs received for that same TCP connection. This would have
 resulted in excess resource consumption due to low mss values.

- CVE-2019-3846: A flaw that allowed an attacker to corrupt memory and possibly
 escalate privileges was found in the mwifiex kernel module while connecting
 to a malicious wireless network. (bnc#1136424)

- CVE-2019-5489: The mincore() implementation in mm/mincore.c in the Linux
 kernel allowed local attackers to observe page cache access patterns of other
 processes on the same system, potentially allowing sniffing of secret
 information. (Fixing this affects the output of the fincore program.) Limited
 remote exploitation may have been possible, as demonstrated by latency differences
 in accessing public files from an Apache HTTP Server. (bnc#1120843)

- CVE-2019-11833: fs/ext4/extents.c in the Linux kernel did not zero out the
 unused memory region in the extent tree block, which might have allowed local users
 to obtain sensitive information by reading uninitialized data in the
 filesystem. (bnc#1135281)

- CVE-2019-11190: The Linux kernel allowed local users to bypass ASLR on setuid
 programs (such as /bin/su) because install_exec_creds() is called too late in
 load_elf_binary() in fs/binfmt_elf.c, and thus the ptrace_may_access() check
 has a race condition when reading /proc/pid/stat. (bnc#1131543)

- CVE-2019-11884: The do_hidp_sock_ioctl function in net/bluetooth/hidp/sock.c
 in the Linux kernel allowed a local user to obtain potentially sensitive
 information from kernel stack memory via a HIDPCONNADD command, because a
 name field may not end with a '\0' character. (bnc#1134848)

- CVE-2018-17972: An issue was discovered in the proc_pid_stack function in
 fs/proc/base.c in the Linux kernel It did not ensure that only root may
 inspect the kernel stack of an arbitrary task, allowing a local attacker to
 exploit racy stack unwinding and leak kernel task stack contents.
 (bnc#1110785)

The following non-security bugs were fixed:

- kabi: drop LINUX_MIB_TCPWQUEUETOOBIG snmp counter ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debuginfo", rpm:"kernel-ec2-debuginfo~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-debugsource", rpm:"kernel-ec2-debugsource~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-extra-debuginfo", rpm:"kernel-ec2-extra-debuginfo~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.61~52.154.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_154-default", rpm:"kgraft-patch-3_12_61-52_154-default~1~1.5.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kgraft-patch-3_12_61-52_154-xen", rpm:"kgraft-patch-3_12_61-52_154-xen~1~1.5.1", rls:"SLES12.0"))) {
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
