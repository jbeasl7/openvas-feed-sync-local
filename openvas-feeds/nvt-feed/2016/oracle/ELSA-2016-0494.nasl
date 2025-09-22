# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122906");
  script_cve_id("CVE-2016-0774");
  script_tag(name:"creation_date", value:"2016-03-23 05:08:54 +0000 (Wed, 23 Mar 2016)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:18:00 +0000 (Sat, 03 Dec 2016)");

  script_name("Oracle: Security Advisory (ELSA-2016-0494)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0494");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0494.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2016-0494 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-573.22.1]
- [mm] always decrement anon_vma degree when the vma list is empty (Jerome Marchand) [1318364 1309898]

[2.6.32-573.21.1]
- [fs] pipe: fix offset and len mismatch on pipe_iov_copy_to_user failure (Seth Jennings) [1310148 1302223] {CVE-2016-0774}
- [fs] gfs2: Add missing else in trans_add_meta/data (Robert S Peterson) [1304332 1267995]
- [fs] fs-cache: Synchronise object death state change vs operation submission (David Howells) [1308471 1096893]
- [fs] fs-cache: Reduce cookie ref count if submit fails (David Howells) [1308471 1096893]
- [mm] memcg: oom_notify use-after-free fix (Rafael Aquini) [1302763 1294400]
- [x86] fix corruption of XMM registers when interrupt handlers use FPU (Mikulas Patocka) [1298994 1259023]
- [net] tcp: honour SO_BINDTODEVICE for TW_RST case too (Florian Westphal) [1303044 1292300]
- [net] add inet_sk_transparent() helper (Florian Westphal) [1303044 1292300]
- [net] ipv6: tcp_ipv6 policy route issue (Florian Westphal) [1303044 1292300]
- [net] ipv6: reuse rt6_need_strict (Florian Westphal) [1303044 1292300]
- [net] tcp: resets are misrouted (Florian Westphal) [1303044 1292300]
- [net] tcp: tcp_v4_send_reset: binding oif to if in no sock case (Florian Westphal) [1303044 1292300]
- [crypto] api: Only abort operations on fatal signal (Herbert Xu) [1296014 1272314]
- [crypto] testmgr: don't use interruptible wait in tests (Herbert Xu) [1296014 1272314]
- [kernel] sched: add wait_for_completion_killable_timeout (Herbert Xu) [1296014 1272314]
- [net] sctp: add routing output fallback (Xin Long) [1307073 1229124]
- [net] sctp: fix dst leak (Xin Long) [1307073 1229124]
- [net] sctp: fix src address selection if using secondary addresses (Xin Long) [1307073 1229124]
- [net] sctp: reduce indent level on sctp_v4_get_dst (Xin Long) [1307073 1229124]
- [scsi] hpsa: Update driver revision to RH5 (Joseph Szczypek) [1306192 1244959]
- [scsi] hpsa: fix issues with multilun devices (Joseph Szczypek) [1306192 1244959]

[2.6.32-573.20.1]
- [sched] kernel: sched: Fix nohz load accounting -- again (Rafael Aquini) [1300349 1167755]
- [sched] kernel: sched: Move sched_avg_update to update_cpu_load (Rafael Aquini) [1300349 1167755]
- [sched] kernel: sched: Cure more NO_HZ load average woes (Rafael Aquini) [1300349 1167755]
- [sched] kernel: sched: Cure load average vs NO_HZ woes (Rafael Aquini) [1300349 1167755]

[2.6.32-573.19.1]
- [scsi] lpfc: in sli3 use configured sg_seg_cnt for sg_tablesize (Rob Evers) [1297838 1227036]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~573.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~573.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~573.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~573.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~573.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~573.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~573.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~573.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~573.22.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~573.22.1.el6", rls:"OracleLinux6"))) {
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
