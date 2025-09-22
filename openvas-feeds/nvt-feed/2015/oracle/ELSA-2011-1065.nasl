# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122122");
  script_cve_id("CVE-2011-1780", "CVE-2011-2525", "CVE-2011-2689");
  script_tag(name:"creation_date", value:"2015-10-06 11:13:26 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 15:13:00 +0000 (Tue, 04 Aug 2020)");

  script_name("Oracle: Security Advisory (ELSA-2011-1065)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1065");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1065.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel, ocfs2-2.6.18-274.el5, oracleasm-2.6.18-274.el5' package(s) announced via the ELSA-2011-1065 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.6.18-274.el5]
- [xen] svm: fix invlpg emulator regression (Paolo Bonzini) [719894]

[2.6.18-273.el5]
- Revert: [fs] proc: Fix rmmod/read/write races in /proc entries (Jarod Wilson) [717068]
- [xen] disregard trailing bytes in an invalid page (Paolo Bonzini) [717742]
- [xen] prep __get_instruction_length_from_list for partial buffers (Paolo Bonzini) [717742]
- [xen] remove unused argument to __get_instruction_length (Paolo Bonzini) [717742]
- [xen] let __get_instruction_length always read into own buffer (Paolo Bonzini) [717742]

[2.6.18-272.el5]
- [xen] x86: spinlock support for up to 255 CPUs (Laszlo Ersek) [713123]
- [xen] remove block scope mtrr identifiers shadowing file scope (Laszlo Ersek) [713123]
- [xen] Actually hold back MTRR init while booting secondary CPUs (Laszlo Ersek) [713123]
- [xen] remove unused mtrr_bp_restore (Laszlo Ersek) [713123]
- [xen] x86: Fix crash on amd iommu systems (Igor Mammedov) [714275]

[2.6.18-271.el5]
- [net] igmp: ip_mc_clear_src only when we no users of ip_mc_list (Veaceslav Falico) [707179]
- [scsi] cxgb3i: fix programming of dma page sizes (Neil Horman) [710498]
- [xen] hvm: secure vmx cpuid (Andrew Jones) [706325] {CVE-2011-1936}
- [xen] hvm: secure svm_cr_access (Andrew Jones) [703716] {CVE-2011-1780}
- [xen] hvm: svm support cleanups (Andrew Jones) [703716] {CVE-2011-1780}

[2.6.18-270.el5]
- [fs] proc: fix compile warning in pdeaux addition (Jarod Wilson) [675781]
- [net] bluetooth: l2cap and rfcomm: fix info leak to userspace (Thomas Graf) [703021]
- [net] inet_diag: fix inet_diag_bc_audit data validation (Thomas Graf) [714539] {CVE-2011-2213}
- [misc] signal: fix kill signal spoofing issue (Oleg Nesterov) [690031] {CVE-2011-1182}
- [fs] proc: fix signedness issue in next_pidmap (Oleg Nesterov) [697827] {CVE-2011-1593}
- [char] agp: fix OOM and buffer overflow (Jerome Marchand) [699010] {CVE-2011-1746}
- [char] agp: fix arbitrary kernel memory writes (Jerome Marchand) [699006] {CVE-2011-1745 CVE-2011-2022}
- [net] be2net: fix queue creation order and pci error recovery (Ivan Vecera) [711653]
- [infiniband] core: Handle large number of entries in poll CQ (Jay Fenlason) [668371] {CVE-2010-4649 CVE-2011-1044}
- [infiniband] core: fix panic in ib_cm:cm_work_handler (Jay Fenlason) [679996] {CVE-2011-0695}
- [fs] validate size of EFI GUID partition entries (Anton Arapov) [703026] {CVE-2011-1776}

[2.6.18-269.el5]
- [mm] only throttle page dirtying for specially marked BDIs (Jeff Layton) [711450]
- Revert: [base] Fix potential deadlock in driver core (Don Zickus) [703084]
- [fs] proc: Fix rmmod/read/write races in /proc entries (David Howells) [675781]
- [scsi] qla4xxx: Update driver version to V5.02.04.01.05.07-d0 (Chad Dupuis) [704153]
- [scsi] qla4xxx: clear SCSI COMPLETION INTR bit during F/W init (Chad Dupuis) [704153]
- [usb] wacom: add support for DTU-2231 (Aristeu Rozanski) [683549]
- [xen] fix MAX_EVTCHNS definition ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel, ocfs2-2.6.18-274.el5, oracleasm-2.6.18-274.el5' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~274.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~274.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~274.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~274.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~274.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~274.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~274.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~274.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~274.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~274.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-274.el5", rpm:"ocfs2-2.6.18-274.el5~1.4.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-274.el5PAE", rpm:"ocfs2-2.6.18-274.el5PAE~1.4.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-274.el5debug", rpm:"ocfs2-2.6.18-274.el5debug~1.4.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-2.6.18-274.el5xen", rpm:"ocfs2-2.6.18-274.el5xen~1.4.8~2.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-274.el5", rpm:"oracleasm-2.6.18-274.el5~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-274.el5PAE", rpm:"oracleasm-2.6.18-274.el5PAE~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-274.el5debug", rpm:"oracleasm-2.6.18-274.el5debug~2.0.5~1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oracleasm-2.6.18-274.el5xen", rpm:"oracleasm-2.6.18-274.el5xen~2.0.5~1.el5", rls:"OracleLinux5"))) {
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
