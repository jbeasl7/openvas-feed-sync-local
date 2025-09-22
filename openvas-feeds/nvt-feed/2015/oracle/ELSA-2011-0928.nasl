# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122136");
  script_cve_id("CVE-2011-1767", "CVE-2011-1768", "CVE-2011-2479");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:39 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 19:56:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-0928)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0928");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0928.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the ELSA-2011-0928 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.32-131.6.1.el6]
- [audit] ia32entry.S sign extend error codes when calling 64 bit code (Eric Paris) [713831 703935]
- [audit] push audit success and retcode into arch ptrace.h (Eric Paris) [713831 703935]
- [x86] intel-iommu: Flush unmaps at domain_exit (Alex Williamson) [713458 705441]
- [x86] intel-iommu: Only unlink device domains from iommu (Alex Williamson) [713458 705441]
- [virt] x86: Mask out unsupported CPUID features if running on xen (Igor Mammedov) [711546 703055]
- [block] fix accounting bug on cross partition merges (Jerome Marchand) [682989 669363]
- [net] vlan: remove multiqueue ability from vlan device (Neil Horman) [713494 703245]
- [net] Fix netif_set_real_num_tx_queues (Neil Horman) [713492 702742]
- [scsi] mpt2sas: move event handling of MPT2SAS_TURN_ON_FAULT_LED in process context (Tomas Henzl) [714190 701951]
- [mm] thp: simple fix for /dev/zero THP mprotect bug (Andrea Arcangeli) [714762 690444]

[2.6.32-131.5.1.el6]
- [kernel] cgroupfs: use init_cred when populating new cgroupfs mount (Eric Paris) [713135 700538]
- [netdrv] ixgbe: adding FdirMode module option (Andy Gospodarek) [711550 707287]
- [crypto] testmgr: add xts-aes-256 self-test (Jarod Wilson) [711548 706167]
- [fs] ext3: Fix lost extended attributes for inode with ino == 11 (Eric Sandeen) [712413 662666]
- [mm] Prevent Disk IO throughput degradation due to memory allocation stalls (Larry Woodman) [711540 679526]
- [net] sock: adjust prot->obj_size always (Jiri Pirko) [709381 704231]
- [fs] GFS2: resource group bitmap corruption resulting in panics and withdraws (Robert S Peterson) [711528 702057]
- [x86] kprobes: Disable irqs during optimized callback (Jiri Olsa) [711545 699865]
- [mm] slab, kmemleak: pass the correct pointer to kmemleak_erase() (Steve Best) [712414 698023]
- [net] fix netns vs proto registration ordering (Wade Mealing) [702305 702306] {CVE-2011-1767 CVE-2011-1768}
- [ppc] Fix oops if scan_dispatch_log is called too early (Steve Best) [711524 696777]
- [virt] i8259: initialize isr_ack (Avi Kivity) [711520 670765]
- [virt] VMX: Save and restore tr selector across mode switches (Gleb Natapov) [711535 693894]
- [virt] VMX: update live TR selector if it changes in real mode (Gleb Natapov) [711535 693894]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~131.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~131.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~131.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~131.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~131.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~131.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~131.6.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~131.6.1.el6", rls:"OracleLinux6"))) {
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
