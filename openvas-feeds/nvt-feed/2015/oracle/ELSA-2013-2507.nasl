# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123694");
  script_cve_id("CVE-2013-0228", "CVE-2013-0309", "CVE-2013-0310", "CVE-2013-0311");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:20 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-2507)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-2507");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-2507.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek' package(s) announced via the ELSA-2013-2507 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.39-400.17.1]
- This is a fix on dlm_clean_master_list() (Xiaowei.Hu)
- RDS: fix rds-ping spinlock recursion (jeff.liu) [Orabug: 16223050]
- vhost: fix length for cross region descriptor (Michael S. Tsirkin) [Orabug:
16387183] {CVE-2013-0311}
- kabifix: block/scsi: Allow request and error handling timeouts to be
specified (Maxim Uvarov)
- block/scsi: Allow request and error handling timeouts to be specified (Martin
K. Petersen) [Orabug: 16372401]
- [SCSI] Shorten the path length of scsi_cmd_to_driver() (Li Zhong) [Orabug:
16372401]
- Fix NULL dereferences in scsi_cmd_to_driver (Mark Rustad) [Orabug: 16372401]
- SCSI: Fix error handling when no ULD is attached (Martin K. Petersen)
[Orabug: 16372401]
- Handle disk devices which can not process medium access commands (Martin K.
Petersen) [Orabug: 16372401]
- the ac->ac_allow_chain_relink=0 won't disable group relink (Xiaowei.Hu)
[Orabug: 14842737]
- pci: hotplug: fix null dereference in pci_set_payload() (Jerry Snitselaar)
[Orabug: 16345420]

[2.6.39-400.16.0]
- epoll: prevent missed events on EPOLL_CTL_MOD (Eric Wong) [Orabug: 16363540]
- rds: this resolved crash while removing rds_rdma module. orabug: 16268201
(Bang Nguyen) [Orabug: 16268201]
- rds: scheduling while atomic on failover orabug: 16275095 (Bang Nguyen)
[Orabug: 16268201]
- SRP: Revert back to 2.6.39-400.8.0 code (Ajaykumar Hotchandani) [Orabug:
16268201]
- iSER: Revert back to 2.6.39-400.8.0 code (Ajaykumar Hotchandani) [Orabug:
16268201]

[2.6.39-400.15.0]
- x86/xen: don't assume %ds is usable in xen_iret for 32-bit PVOPS. (Jan
Beulich) {CVE-2013-0228}
- xen-blkfront: drop the use of llist_for_each_entry_safe (Konrad Rzeszutek
Wilk) [Orabug: 16263164]
- Revert 'xen PVonHVM: use E820_Reserved area for shared_info' (Konrad
Rzeszutek Wilk) [Orabug: 16297716]
- Revert 'xen/PVonHVM: fix compile warning in init_hvm_pv_info' (Konrad
Rzeszutek Wilk)

[2.6.39-400.14.0]
- xfs: use shared ilock mode for direct IO writes by default (Dave Chinner)
[Orabug: 16304938]
- sched: fix divide by zero at {thread_group,task}_times (Stanislaw Gruszka)
[Orabug: 15956690]
- Revert 'Revert 'cgroup: notify_on_release may not be triggered in some
cases'' (Maxim Uvarov)
- xen_fmr: Verify XEN platform before running xen_fmr drivers (Yuval Shaia)
[Orabug: 16302435]
- rds: unregister IB event handler on shutdown (Bang Nguyen) [Orabug: 16302435]
- rds: HAIP support child interface (Bang Nguyen) [Orabug: 16302435]
- RDS HAIP misc fixes (Bang Nguyen) [Orabug: 16302435]
- Ignore failover groups if HAIP is disabled (Bang Nguyen) [Orabug: 16302435]
- RDS: RDS rolling upgrade (Saeed Mahameed) [Orabug: 16302435]
- mlx4_core: use correct FMR number of clients according to PRM. (Saeed
Mahameed) [Orabug: 16302435]

[2.6.39-400.13.0]
- kmod: make __request_module() killable (Oleg Nesterov) [Orabug: 16286305]
{CVE-2012-4398}
- kmod: introduce call_modprobe() helper (Oleg Nesterov) [Orabug: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.17.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.17.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.17.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.17.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.17.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.17.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.17.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.17.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.17.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.17.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.17.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.17.1.el6uek", rls:"OracleLinux6"))) {
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
