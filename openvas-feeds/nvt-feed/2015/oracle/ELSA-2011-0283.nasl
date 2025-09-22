# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122239");
  script_cve_id("CVE-2010-4165", "CVE-2010-4169", "CVE-2010-4243");
  script_tag(name:"creation_date", value:"2015-10-06 11:15:16 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2011-0283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0283");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0283.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2011-0283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-71.18.1.el6]
- [netdrv] ixgbe: make sure FCoE DDP user buffers are really released by the HW (Frantisek Hrbata) [674002 617193]
- [netdrv] ixgbe: invalidate FCoE DDP context when no error status is available (Frantisek Hrbata) [674002 617193]
- [netdrv] ixgbe: avoid doing FCoE DDP when adapter is DOWN or RESETTING (Frantisek Hrbata) [674002 617193]
- [fcoe] libfc: remove tgt_flags from fc_fcp_pkt struct (Mike Christie) [666797 633915]
- [fcoe] libfc: use rport timeout values for fcp recovery (Frantisek Hrbata) [666797 633915]
- [fcoe] libfc: incorrect scsi host byte codes returned to scsi-ml (Mike Christie) [666797 633915]
- [scsi] scsi_dh_alua: fix overflow in alua_rtpg port group id check (Mike Snitzer) [673978 670572]

[2.6.32-71.17.1.el6]
- [s390x] kdump: allow zfcpdump to mount and write to ext4 file systems (Amerigo Wang) [661667 628676]
- [scsi] qla2xxx: Properly set the return value in function qla2xxx_eh_abort (Chad Dupuis) [664398 635710]
- [scsi] qla2xxx: Drop srb reference before waiting for completion (Chad Dupuis) [664398 635710]
- [virt] KVM: VMX: Really clear cr0.ts when giving the guest ownership of the fpu (Avi Kivity) [658891 645898]
- [virt] KVM: SVM: Initialize fpu_active in init_vmcb() (Avi Kivity) [658891 645898]
- [virt] KVM: x86: Use unlazy_fpu() for host FPU (Avi Kivity) [658891 645898]
- [virt] KVM: Set cr0.et when the guest writes cr0 (Avi Kivity) [658891 645898]
- [virt] KVM: VMX: Give the guest ownership of cr0.ts when the fpu is active (Avi Kivity) [658891 645898]
- [virt] KVM: Lazify fpu activation and deactivation (Avi Kivity) [658891 645898]
- [virt] KVM: VMX: Allow the guest to own some cr0 bits (Avi Kivity) [658891 645898]
- [virt] KVM: Replace read accesses of vcpu->arch.cr0 by an accessor (Avi Kivity) [658891 645898]
- [virt] KVM: VMX: trace clts and lmsw instructions as cr accesses (Avi Kivity) [658891 645898]

[2.6.32-71.16.1.el6]
- [net] ipsec: fragment locally generated tunnel-mode IPSec6 packets as needed (Herbert Xu) [670421 661113]
- [net] tcp: Increase TCP_MAXSEG socket option minimum to TCP_MIN_MSS (Frantisek Hrbata) [652510 652511] {CVE-2010-4165}
- [perf] perf_events: Fix perf_counter_mmap() hook in mprotect() (Oleg Nesterov) [651672 651673] {CVE-2010-4169}
- [md] dm mpath: revert 'dm: Call blk_abort_queue on failed paths' (Mike Snitzer) [658854 636771]
- [x86] UV: Address interrupt/IO port operation conflict (George Beshers) [662921 659480]
- [mm] guard page for stacks that grow upwards (Johannes Weiner) [666796 630562]
- [scsi] enable state transitions from OFFLINE to RUNNING (Mike Christie) [660590 643237]
- [scsi] set queue limits no_cluster for stacked devices (Mike Snitzer) [662050 658293]
- [mm] Out-of-memory under memory cgroup can call both of oom-killer-for-memcg and oom-killer-for-page-fault (Larry Woodman) [661732 592879]
- [scsi] libfc: possible race could panic system due to NULL fsp->cmd (Mike ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~71.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~71.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~71.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~71.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~71.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~71.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~71.18.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~71.18.1.el6", rls:"OracleLinux6"))) {
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
