# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123416");
  script_cve_id("CVE-2013-6383", "CVE-2014-0077", "CVE-2014-2523");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:30 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-0475)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0475");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0475.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-0475 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-431.17.1]
- [scsi] qla2xxx: Fixup looking for a space in the outstanding_cmds array in qla2x00_alloc_iocbs() (Chad Dupuis) [1085660 1070856]
- [scsi] isci: fix reset timeout handling (David Milburn) [1080600 1040393]
- [scsi] isci: correct erroneous for_each_isci_host macro (David Milburn) [1074855 1059325]
- [kernel] sched: Fix small race where child->se.parent, cfs_rq might point to invalid ones (Naoya Horiguchi) [1081907 1032350]
- [kernel] sched: suppress RCU lockdep splat in task_fork_fair (Naoya Horiguchi) [1081907 1032350]
- [kernel] sched: add local variable to store task_group() to avoid kernel stall (Naoya Horiguchi) [1081908 1043733]
- [fs] cifs: mask off top byte in get_rfc1002_length() (Sachin Prabhu) [1085358 1069737]
- [kernel] Prevent deadlock when post_schedule_rt() results in calling wakeup_kswapd() on multiple CPUs (Larry Woodman) [1086095 1009626]
- [scsi] AACRAID Driver compat IOCTL missing capability check (Jacob Tanenbaum) [1033533 1033534] {CVE-2013-6383}
- [md] dm-thin: fix rcu_read_lock being held in code that can sleep (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: irqsave must always be used with the pool->lock spinlock (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: sort the per thin deferred bios using an rb_tree (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: use per thin device deferred bio lists (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: simplify pool_is_congested (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: fix dangling bio in process_deferred_bios error path (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: take care to copy the space map root before locking the superblock (Mike Snitzer) [1086007 1060381]
- [md] dm-transaction-manager: fix corruption due to non-atomic transaction commit (Mike Snitzer) [1086007 1060381]
- [md] dm-space-map-metadata: fix refcount decrement below 0 which caused corruption (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: fix Documentation for held metadata root feature (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: fix noflush suspend IO queueing (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: fix deadlock in __requeue_bio_list (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: fix out of data space handling (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: ensure user takes action to validate data and metadata consistency (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: synchronize the pool mode during suspend (Mike Snitzer) [1086007 1060381]
- [md] fix Kconfig indentation (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: allow metadata space larger than supported to go unused (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: fix the error path for the thin device constructor (Mike Snitzer) [1086007 1060381]
- [md] dm-thin: avoid metadata commit if a pool's thin devices haven't changed (Mike Snitzer) [1086007 1060381]
- [md] dm-space-map-metadata: fix bug in resizing of thin metadata ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.17.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.17.1.el6", rls:"OracleLinux6"))) {
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
