# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123234");
  script_cve_id("CVE-2014-1739", "CVE-2014-3184", "CVE-2014-4014", "CVE-2014-4171");
  script_tag(name:"creation_date", value:"2015-10-06 11:01:05 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-3096)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-3096");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-3096.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dtrace-modules-3.8.13-55.el6uek, dtrace-modules-3.8.13-55.el7uek, kernel-uek' package(s) announced via the ELSA-2014-3096 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[3.8.13-55]
- freezer: set PF_SUSPEND_TASK flag on tasks that call freeze_processes (Colin Cross) [Orabug: 20082843]

[3.8.13-54]
- netfilter: nf_nat: fix oops on netns removal (Florian Westphal) [Orabug: 19988779]
- tcp: tsq: restore minimal amount of queueing (Eric Dumazet) [Orabug: 19909542]
- qedf: Fixes for compilation issues on oracle uek3r4. (Saurav Kashyap) [Orabug: 20027243]
- qla2xxx: fix wrongly report 'PCI EEH busy' when get_thermal_temp (Vaughan Cao) [Orabug: 19916135]
- Revert 'ib_cm: reduce latency when destroying large number of ids' (Guangyu Sun) [Orabug: 20012864]
- Revert 'rds: avoid duplicate connection drops for active bonding' (Guangyu Sun) [Orabug: 20012864]
- xen/pciback: Restore configuration space when detaching from a guest. (Konrad Rzeszutek Wilk) [Orabug: 19970142]
- cpufreq: remove race while accessing cur_policy (Bibek Basu) [Orabug: 19945473]
- cpufreq: serialize calls to __cpufreq_governor() (Viresh Kumar) [Orabug: 19945473]
- cpufreq: don't allow governor limits to be changed when it is disabled (Viresh Kumar) [Orabug: 19945473]
- net: sctp: fix panic on duplicate ASCONF chunks (Daniel Borkmann) [Orabug: 19953088] {CVE-2014-3687}
- net: sctp: fix skb_over_panic when receiving malformed ASCONF chunks (Daniel Borkmann) [Orabug: 19953087] {CVE-2014-3673}
- perf/x86: Check all MSRs before passing hw check (George Dunlap) [Orabug: 19803968]
- o2dlm: fix NULL pointer dereference in o2dlm_blocking_ast_wrapper (Srinivas Eeda) [Orabug: 19825227]
- RDS: add module parameter to allow module unload or not (Wengang Wang) [Orabug: 19927376]
- dwarf2ctf: don't use O_PATH in rel_abs_file_name(). (Jamie Iles) [Orabug: 19957565]
- dwarf2ctf: don't leak directory fd. (Jamie Iles) [Orabug: 19957565]

[3.8.13-53]
- net: reset mac header in dev_start_xmit() (Eric Dumazet) [Orabug: 19951043]

[3.8.13-52]
- xen/efi: rebased version of xen.efi (Jan Beulich) [Orabug: 19878307]

[3.8.13-51]
- config: enable pm80xx module (Guangyu Sun) [Orabug: 19890236]
- free ib_device related resource (Wengang Wang) [Orabug: 19479464]
- srq initialization and cleanup -v3.1 (Wengang Wang) [Orabug: 19010606]
- rds: avoid duplicate connection drops for active bonding (Ajaykumar Hotchandani) [Orabug: 19870095]
- ib_cm: reduce latency when destroying large number of ids (Ajaykumar Hotchandani) [Orabug: 19870101]
- IPoIB: Change default IPOIB_RX_RING_SIZE to 2048 (Chien-Hua Yen) [Orabug: 19870157]
- ipv6: ip6_dst_check needs to check for expired dst_entries (Hannes Frederic Sowa) [Orabug: 19073604]
- netxen: Fix bug in Tx completion path. (Manish Chopra) [Orabug: 19877613]
- netxen: Fix BUG 'sleeping function called from invalid context' (Manish Chopra) [Orabug: 19877613]
- drivers/net: Convert remaining uses of pr_warning to pr_warn (Joe Perches) [Orabug: 19877613]
- treewide: Fix typo in printk (Masanari Iida) [Orabug: 19877613]
- PCI: Remove DEFINE_PCI_DEVICE_TABLE macro ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dtrace-modules-3.8.13-55.el6uek, dtrace-modules-3.8.13-55.el7uek, kernel-uek' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-55.el6uek", rpm:"dtrace-modules-3.8.13-55.el6uek~0.4.3~4.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~55.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~55.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~55.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~55.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~55.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~55.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"dtrace-modules-3.8.13-55.el7uek", rpm:"dtrace-modules-3.8.13-55.el7uek~0.4.3~4.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~55.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~55.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~55.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~55.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~55.el7uek", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~55.el7uek", rls:"OracleLinux7"))) {
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
