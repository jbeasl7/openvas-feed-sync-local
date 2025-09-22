# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122434");
  script_cve_id("CVE-2009-3290");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:18 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-1465)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1465");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1465.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2009-1465 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[83-105.0.1.el5_4.7]
- Add kvm-add-oracle-workaround-for-libvirt-bug.patch

[kvm-83-105.el5_4.7]
- kvm-qemu-virtio-net-do-not-return-stack-pointer-from-fun.patch [bz#524557]
- Resolves: bz#524557
 (QEMU crash (during virtio-net WHQL tests for Win2008 R2))

[kvm-83-105.el5_4.6]
- kvm-Revert-update_refcount-Write-complete-sectors.patch [bz#520693]
- kvm-Revert-alloc_cluster_link_l2-Write-complete-sectors.patch [bz#520693]
- kvm-Revert-Combined-patch-of-two-upstream-commits-the-se.patch [bz#520693]
- kvm-Revert-qcow2-Update-multiple-refcounts-at-once.patch [bz#520693]
- kvm-Revert-qcow2-Refactor-update_refcount.patch [bz#520693]
- Related: bz#520693
 (Bad qcow2 performance with cache=off)

[kvm-83-105.el5_4.5]
- kvm-kernel-KVM-VMX-Optimize-vmx_get_cpl.patch [bz#524125 bz#524125]
- kvm-kernel-KVM-x86-Disallow-hypercalls-for-guest-callers-in-rin.patch [bz#524125 bz#524125]
- Resolves: bz#524125
 (kernel: KVM: x86: Disallow hypercalls for guest callers in rings > 0 [rhel-5.4.z])

[83-105.el5_4.4]
- kvm-kernel-reset-hflags-on-cpu-reset.patch [bz#520694]
- Resolves: bz#520694
 (NMI filtering for AMD (Windows 2008 R2 KVM guest can not restart when set it as multiple cpus))

[83-105.el5_4.3]
- kvm-kernel-Fix-coalesced-interrupt-reporting-in-IOAPIC.patch [bz#521794]
- kvm-kernel-VMX-Fix-cr8-exiting-control-clobbering-by-EPT.patch [bz#521793]
- Resolves: bz#521793
 (windows 64 bit does vmexit on each cr8 access.)
- Resolves: bz#521794
 (rtc-td-hack stopped working. Time drifts in windows)
- kvm-qcow2-Refactor-update_refcount.patch [bz#520693]
- kvm-qcow2-Update-multiple-refcounts-at-once.patch [bz#520693]
- kvm-Combined-patch-of-two-upstream-commits-the-second-fi.patch [bz#520693]
- kvm-alloc_cluster_link_l2-Write-complete-sectors.patch [bz#520693]
- kvm-update_refcount-Write-complete-sectors.patch [bz#520693]
- Resolves: bz#520693
 (Bad qcow2 performance with cache=off)

[83-105.el5_4.2]
- Update kversion to 2.6.18-164.el5 to match build root
- kvm-kernel-add-nmi-support-to-svm.patch [bz#520694]
- Resolves: bz#520694
 (NMI filtering for AMD (Windows 2008 R2 KVM guest can not restart when set it as multiple cpus))

[83-105.el5_4.1]
- Update kversion to 2.6.18-162.el5
- kvm-Initialize-PS2-keyboard-mouse-state-on-reset.patch [bz#517855]
- Resolves: bz#517855
 (guest not accepting keystrokes or mouse clicks after reboot)");

  script_tag(name:"affected", value:"'kvm' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~105.0.1.el5_4.7", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~105.0.1.el5_4.7", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~105.0.1.el5_4.7", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~105.0.1.el5_4.7", rls:"OracleLinux5"))) {
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
