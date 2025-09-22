# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123347");
  script_cve_id("CVE-2012-6647", "CVE-2013-7339", "CVE-2014-2672", "CVE-2014-2678", "CVE-2014-2706", "CVE-2014-2851", "CVE-2014-3144", "CVE-2014-3145");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:35 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-0981)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0981");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0981.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2014-0981 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-431.23.3]
- [netdrv] pppol2tp: fail when socket option level is not SOL_PPPOL2TP [1119461 1119462] {CVE-2014-4943}

[2.6.32-431.23.2]
- [kernel] utrace: force IRET path after utrace_finish_vfork() (Oleg Nesterov) [1115932 1115933] {CVE-2014-4699}

[2.6.32-431.23.1]
- [net] ip_tunnel: fix ip_tunnel_find to return NULL in case the tunnel is not there (Jiri Pirko) [1107931 1104503]
- [netdrv] bnx2x: Fix kernel crash and data miscompare after EEH recovery (Michal Schmidt) [1109269 1029600]
- [netdrv] bnx2x: Adapter not recovery from EEH error injection (Michal Schmidt) [1109269 1029600]
- [scsi] qla2xxx: Don't check for firmware hung during the reset context for ISP82XX (Chad Dupuis) [1110658 1054299]
- [scsi] qla2xxx: Clear loop_id for ports that are marked lost during fabric scanning (Chad Dupuis) [1110658 1054299]
- [scsi] qla2xxx: Issue abort command for outstanding commands during cleanup when only firmware is alive (Chad Dupuis) [1110658 1054299]
- [scsi] qla2xxx: Reduce the time we wait for a command to complete during SCSI error handling (Chad Dupuis) [1110658 1054299]
- [scsi] qla2xxx: Avoid escalating the SCSI error handler if the command is not found in firmware (Chad Dupuis) [1110658 1054299]
- [scsi] qla2xxx: Set host can_queue value based on available resources (Chad Dupuis) [1110658 1054299]
- [net] filter: prevent nla extensions to peek beyond the end of the message (Jiri Benc) [1096778 1096779] {CVE-2014-3144 CVE-2014-3145}
- [net] bridge: add empty br_mdb_init() and br_mdb_uninit() definitions (Vlad Yasevich) [1106472 1097915]
- [net] bridge: Correctly unregister MDB rtnetlink handlers (Vlad Yasevich) [1106472 1097915]
- [net] rds: prevent dereference of a NULL device in rds_iw_laddr_check (Radomir Vrbovsky) [1083276 1083277] {CVE-2014-2678}
- [s390] crypto: fix aes, des ctr mode concurrency finding (Hendrik Brueckner) [1110168 1096328]
- [s390] crypto: fix des and des3_ede ctr concurrency issue (Hendrik Brueckner) [1109885 1065404]
- [s390] crypto: fix des and des3_ede cbc concurrency issue (Hendrik Brueckner) [1109883 1065398]
- [kernel] futex: Forbid uaddr == uaddr2 in futex_wait_requeue_pi() (Mateusz Guzik) [1097759 1097760] {CVE-2012-6647}
- [libata] ahci: accommodate tag ordered controller (David Milburn) [1099725 1083748]
- [net] mac80211: crash dues to AP powersave TX vs. wakeup race (Jacob Tanenbaum) [1083531 1083532] {CVE-2014-2706}
- [netdrv] ath9k: tid->sched race in ath_tx_aggr_sleep() (Jacob Tanenbaum) [1083249 1083250] {CVE-2014-2672}
- [kernel] hrtimer: Prevent all reprogramming if hang detected (Prarit Bhargava) [1096059 1075805]
- [net] ipv4: current group_info should be put after using (Jiri Benc) [1087412 1087414] {CVE-2014-2851}
- [kernel] tracing: Reset ring buffer when changing trace_clocks (Marcelo Tosatti) [1093984 1018138]
- [net] rds: dereference of a NULL device (Jacob Tanenbaum) [1079218 1079219] {CVE-2013-7339}
- [s390] ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.23.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.23.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.23.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.23.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.23.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.23.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.23.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.23.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.23.3.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.23.3.el6", rls:"OracleLinux6"))) {
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
