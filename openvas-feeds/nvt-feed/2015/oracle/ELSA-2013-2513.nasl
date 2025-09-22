# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123645");
  script_cve_id("CVE-2013-0871", "CVE-2013-0913", "CVE-2013-1773");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:43 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-2513)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-2513");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-2513.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek' package(s) announced via the ELSA-2013-2513 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.39-400.21.1]
- SPEC: v2.6.39-400.21.1 (Maxim Uvarov)
- xen/mmu: On early bootup, flush the TLB when changing RO->RW bits Xen provided pagetables. (Konrad Rzeszutek Wilk)

[2.6.39-400.20.1]
- SPEC: v2.6.39-400.20.1 (Maxim Uvarov)
- PCI: Set device power state to PCI_D0 for device without native PM support (Ajaykumar Hotchandani) [Orabug: 16482495]
- sched: Fix cgroup movement of waking process (Daisuke Nishimura) [Orabug: 13740515]
- sched: Fix cgroup movement of newly created process (Daisuke Nishimura) [Orabug: 13740515]
- sched: Fix cgroup movement of forking process (Daisuke Nishimura) [Orabug: 13740515]

[2.6.39-400.19.1]
- IB/core: Allow device-specific per-port sysfs files (Ralph Campbell)
- RDMA/cma: Pass QP type into rdma_create_id() (Sean Hefty)
- IB: Rename RAW_ETY to RAW_ETHERTYPE (Aleksey Senin)
- IB: Warning Resolution. (Ajaykumar Hotchandani)
- mlx4_core: fix FMR flags in free MTT range (Saeed Mahameed)
- mlx4_core/ib: sriov fmr bug fixes (Saeed Mahameed)
- mlx4_core: Change bitmap allocator to work in round-robin fashion (Saeed
 Mahameed)
- mlx4_vnic: move host admin vnics to closed state when closing the vnic.
 (Saeed Mahameed)
- mlx4_ib: make sure to flush clean_wq while closing sriov device (Saeed
 Mahameed)
- ib_sdp: fix deadlock when sdp_cma_handler is called while socket is being
 closed (Saeed Mahameed)
- ib_sdp: add unhandled events to rdma_cm_event_str (Saeed Mahameed)
- mlx4_core: use dev->sriov instead of hardcoed 127 vfs when initializing FMR
 MPT tables (Saeed Mahameed)
- mlx4_vnic: print vnic keep alive info in mlx4_vnic_info (Saeed Mahameed)
- rds: Congestion flag does not get cleared causing the connection to hang
 (Bang Nguyen) [Orabug: 16424692]
- dm table: set flush capability based on underlying devices (Mike Snitzer)
 [Orabug: 16392584]
- wake_up_process() should be never used to wakeup a TASK_STOPPED/TRACED task
 (Oleg Nesterov) [Orabug: 16405869] {CVE-2013-0871}
- ptrace: ensure arch_ptrace/ptrace_request can never race with SIGKILL (Oleg
 Nesterov) [Orabug: 16405869] {CVE-2013-0871}
- ptrace: introduce signal_wake_up_state() and ptrace_signal_wake_up() (Oleg
 Nesterov) [Orabug: 16405869] {CVE-2013-0871}
- drm/i915: bounds check execbuffer relocation count (Kees Cook) [Orabug:
 16482650] {CVE-2013-0913}
- NLS: improve UTF8 -> UTF16 string conversion routine (Alan Stern) [Orabug:
 16425571] {CVE-2013-1773}
- ipmi: make kcs timeout parameters as module options (Pavel Bures) [Orabug:
 16470881]
- drm/i915/lvds: ditch ->prepare special case (Daniel Vetter) [Orabug:
 14394113]
- drm/i915: Leave LVDS registers unlocked (Keith Packard) [Orabug: 14394113]
- drm/i915: don't clobber the pipe param in sanitize_modesetting (Daniel
 Vetter) [Orabug: 14394113]
- drm/i915: Sanitize BIOS debugging bits from PIPECONF (Chris Wilson) [Orabug:
 14394113]

[2.6.39-400.18.1]
- SPEC: fix doc build (Guru Anbalagane)
- floppy: Fix a crash during rmmod ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.21.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.21.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.21.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.21.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.21.1.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.21.1.el5uek", rls:"OracleLinux5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.21.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.21.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.21.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.21.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.21.1.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.21.1.el6uek", rls:"OracleLinux6"))) {
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
