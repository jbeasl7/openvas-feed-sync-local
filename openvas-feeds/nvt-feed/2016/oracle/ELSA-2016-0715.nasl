# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122929");
  script_cve_id("CVE-2015-5157", "CVE-2015-8767");
  script_tag(name:"creation_date", value:"2016-05-09 11:24:46 +0000 (Mon, 09 May 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-30 16:53:00 +0000 (Thu, 30 Aug 2018)");

  script_name("Oracle: Security Advisory (ELSA-2016-0715)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0715");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0715.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2016-0715 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-573.26.1]
- [kernel] revert 'sched: core: Use hrtimer_start_expires' (Jiri Olsa) [1326043 1324318]
- [kernel] Revert 'Cleanup bandwidth timers' (Jiri Olsa) [1326043 1324318]
- [kernel] revert 'fair: Test list head instead of list entry in throttle_cfs_rq' (Jiri Olsa) [1326043 1324318]
- [kernel] revert 'sched, perf: Fix periodic timers' (Jiri Olsa) [1326043 1324318]
- [kernel] Revert 'fix KABI break' (Jiri Olsa) [1326043 1324318]

[2.6.32-573.25.1]
- [x86] nmi/64: Fix a paravirt stack-clobbering bug in the NMI code (Denys Vlasenko) [1259580 1259581] {CVE-2015-5157}
- [x86] nmi/64: Switch stacks on userspace NMI entry (Denys Vlasenko) [1259580 1259581] {CVE-2015-5157}
- [fs] anon_inodes implement dname (Aristeu Rozanski) [1322707 1296019]
- [fs] xfs: Avoid pathological backwards allocation (Bill O'Donnell) [1320031 1302777]
- [net] sctp: Prevent soft lockup when sctp_accept() is called during a timeout event (Jacob Tanenbaum) [1297421 1297422] {CVE-2015-8767}
- [net] udp: move logic out of udp[46]_ufo_send_check (Sabrina Dubroca) [1319276 1299975]
- [net] af_unix: Guard against other == sk in unix_dgram_sendmsg (Jakub Sitnicki) [1315696 1309241]
- [md] raid10: don't clear bitmap bit when bad-block-list write fails (Jes Sorensen) [1320863 1273546]
- [md] raid1: don't clear bitmap bit when bad-block-list write fails (Jes Sorensen) [1320863 1273546]
- [md] raid10: submit_bio_wait returns 0 on success (Jes Sorensen) [1320863 1273546]
- [md] raid1: submit_bio_wait() returns 0 on success (Jes Sorensen) [1320863 1273546]
- [md] crash in md-raid1 and md-raid10 due to incorrect list manipulation (Jes Sorensen) [1320863 1273546]
- [md] raid10: ensure device failure recorded before write request returns (Jes Sorensen) [1320863 1273546]
- [md] raid1: ensure device failure recorded before write request returns (Jes Sorensen) [1320863 1273546]

[2.6.32-573.24.1]
- [sched] fix KABI break (Seth Jennings) [1314878 1230310]
- [sched] fair: Test list head instead of list entry in throttle_cfs_rq (Seth Jennings) [1314878 1230310]
- [sched] sched,perf: Fix periodic timers (Seth Jennings) [1314878 1230310]
- [sched] sched: debug: Remove the cfs bandwidth timer_active printout (Seth Jennings) [1314878 1230310]
- [sched] Cleanup bandwidth timers (Seth Jennings) [1314878 1230310]
- [sched] sched: core: Use hrtimer_start_expires (Seth Jennings) [1314878 1230310]
- [sched] fair: Fix unlocked reads of some cfs_b->quota/period (Seth Jennings) [1314878 1230310]
- [sched] Fix potential near-infinite distribute_cfs_runtime loop (Seth Jennings) [1314878 1230310]
- [sched] fair: Fix tg_set_cfs_bandwidth deadlock on rq->lock (Seth Jennings) [1314878 1230310]
- [sched] Fix hrtimer_cancel/rq->lock deadlock (Seth Jennings) [1314878 1230310]
- [sched] Fix cfs_bandwidth misuse of hrtimer_expires_remaining (Seth Jennings) [1314878 1230310]
- [sched] Refine the code in unthrottle_cfs_rq (Seth Jennings) ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~573.26.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~573.26.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~573.26.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~573.26.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~573.26.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~573.26.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~573.26.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~573.26.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~573.26.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~573.26.1.el6", rls:"OracleLinux6"))) {
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
