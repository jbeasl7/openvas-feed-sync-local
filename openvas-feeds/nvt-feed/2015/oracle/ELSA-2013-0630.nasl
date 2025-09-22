# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123664");
  script_cve_id("CVE-2013-0228", "CVE-2013-0268");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:58 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0630)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0630");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0630.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2013-0630 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-358.2.1]
- [kernel] utrace: ensure arch_ptrace/ptrace_request can never race with SIGKILL (Oleg Nesterov) [912073 912074] {CVE-2013-0871}

[2.6.32-358.1.1]
- [netdrv] mlx4: Set number of msix vectors under SRIOV mode to firmware defaults (Michal Schmidt) [911663 904726]
- [netdrv] mlx4: Fix bridged vSwitch configuration for non SRIOV mode (Michal Schmidt) [910998 903644]
- [net] rtnetlink: Fix IFLA_EXT_MASK definition (regression) (Thomas Graf) [909815 903220]
- [x86] msr: Add capabilities check (Nikola Pajkovsky) [908698 908699] {CVE-2013-0268}
- [x86] msr: Remove incorrect, duplicated code in the MSR driver (Nikola Pajkovsky) [908698 908699] {CVE-2013-0268}
- [virt] xen: don't assume ds is usable in xen_iret for 32-bit PVOPS (Andrew Jones) [906310 906311] {CVE-2013-0228}
- [kernel] cputime: Avoid multiplication overflow on utime scaling (Stanislaw Gruszka) [908794 862758]
- [net] sunrpc: When changing the queue priority, ensure that we change the owner (Steve Dickson) [910370 902965]
- [net] sunrpc: Ensure we release the socket write lock if the rpc_task exits early (Steve Dickson) [910370 902965]
- [fs] nfs: Ensure that we free the rpc_task after read and write cleanups are done (Steve Dickson) [910370 902965]
- [net] sunrpc: Ensure that we free the rpc_task after cleanups are done (Steve Dickson) [910370 902965]
- [net] sunrpc: Don't allow low priority tasks to preempt higher priority ones (Steve Dickson) [910370 902965]
- [fs] nfs: Add sequence_priviliged_ops for nfs4_proc_sequence() (Steve Dickson) [910370 902965]
- [fs] nfs: The NFSv4.0 client must send RENEW calls if it holds a delegation (Steve Dickson) [910370 902965]
- [fs] nfs: nfs4_proc_renew should be declared static (Steve Dickson) [910370 902965]
- [fs] nfs: nfs4_locku_done must release the sequence id (Steve Dickson) [910370 902965]
- [fs] nfs: We must release the sequence id when we fail to get a session slot (Steve Dickson) [910370 902965]
- [fs] nfs: Add debugging messages to NFSv4s CLOSE procedure (Steve Dickson) [910370 902965]
- [net] sunrpc: Clear the connect flag when socket state is TCP_CLOSE_WAIT (Steve Dickson) [910370 902965]
- [fs] nfs: cleanup DS stateid error handling (Steve Dickson) [910370 902965]
- [fs] nfs: handle DS stateid errors (Steve Dickson) [910370 902965]
- [fs] nfs: Fix potential races in xprt_lock_write_next() (Steve Dickson) [910370 902965]
- [fs] nfs: Ensure correct locking when accessing the 'lock_states' list (Steve Dickson) [910370 902965]
- [fs] nfs: Fix the handling of NFS4ERR_SEQ_MISORDERED errors (Steve Dickson) [910370 902965]
- [netdrv] be2net: fix unconditionally returning IRQ_HANDLED in INTx (Ivan Vecera) [910373 909464]
- [netdrv] be2net: fix INTx ISR for interrupt behaviour on BE2 (Ivan Vecera) [910373 909464]
- [netdrv] be2net: fix a possible events_get() race on BE2 (Ivan Vecera) [910373 909464]
- [fs] gfs2: Get a block reservation before resizing a ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.2.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.2.1.el6", rls:"OracleLinux6"))) {
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
