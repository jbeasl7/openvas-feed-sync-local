# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122279");
  script_cve_id("CVE-2010-4525");
  script_tag(name:"creation_date", value:"2015-10-06 11:15:52 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2011-0028)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0028");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0028.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2011-0028 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-224.0.1]
- Added kvm-add-oracle-workaround-for-libvirt-bug.patch
- Added kvm-Introduce-oel-machine-type.patch

[kvm-83-224.el5]
- kvm-kernel-KVM-x86-zero-kvm_vcpu_events-interrupt.pad.patch [bz#665407]
- Resolves: bz#665407
 (kvm_vcpu_events.interrupt.pad must be zeroed)
- CVE: CVE-2010-4525

[kvm-83-223.el5]
- Updated kversion to 2.6.18-237.el to match build root
- Reverting patches for bz#608709 as they are not complete
 - kvm-kernel-Revert-KVM-VMX-Return-0-from-a-failed-VMREAD.patch [bz#608709]
 - kvm-kernel-Revert-KVM-Don-t-spin-on-virt-instruction-faults-dur.patch [bz#608709]
- bz#608709: reboot(RB_AUTOBOOT) fails if kvm instance is running
- Related: bz#661117

[kvm-83-222.el5]
- kvm-kernel-kvm-change-signed-int-to-unsigned-in-mmu_shrink.patch [bz#661117]
- Resolves: bz#661117
 ([RHEL5.6 CC] mmu_shrink patch)

[kvm-83-221.el5]
- Updated kversion to 2.6.18-236.el to match build root
- kvm-kernel-KVM-Don-t-spin-on-virt-instruction-faults-during-reb.patch [bz#608709]
- kvm-kernel-KVM-VMX-Return-0-from-a-failed-VMREAD.patch [bz#608709]
- Resolves: bz#608709
 (reboot(RB_AUTOBOOT) fails if kvm instance is running)

[kvm-83-220.el5]
- Updated kversion to 2.6.18-235.el to match build root
- kvm-load-registers-after-restoring-pvclock-msrs.patch [bz#655990]
- Resolves: bz#655990
 (clock drift when migrating a guest between mis-matched CPU clock speed)

[kvm-83-219.el5]
- kvm-kernel-KVM-fix-AMD-initial-TSC-offset-problems-additional-f.patch [bz#642659]
- Resolves: bz#642659
 (TSC offset of virtual machines is not initialized correctly by 'kvm_amd' kernel module.)

[kvm-83-218.el5]
- kvm-vnc-fix-key-event-processing.patch [bz#643317]
- Resolves: bz#643317
 ('sendkey ctrl-alt-delete' don't work via VNC)

[kvm-83-217.el5]
- kvm-kernel-fix-null-pointer-dereference.patch [bz#570532]
- Resolves: bz#570532
 (CVE-2010-0435 kvm: vmx null pointer dereference)
- CVE: CVE-2010-0435

[kvm-83-216.el5]
- Updated kversion to 2.6.18-233.el to match build root
- kvm-kernel-KVM-fix-AMD-initial-TSC-offset-problems.patch [bz#642659]
- Resolves: bz#642659
 (TSC offset of virtual machines is not initialized correctly by 'kvm_amd' kernel module.)

[kvm-83-215.el5]
- Reverts previous patch (it doesn't build)
- kvm-kernel-Revert-KVM-fix-AMD-initial-TSC-bugs.patch [bz#642659]
- Related: bz#642659
 (TSC offset of virtual machines is not initialized correctly by 'kvm_amd' kernel module.)

[kvm-83-214.el5]
- kvm-kernel-KVM-fix-AMD-initial-TSC-bugs.patch [bz#642659]
- Resolves: bz#642659
 (TSC offset of virtual machines is not initialized correctly by 'kvm_amd' kernel module.)

[kvm-83-213.el5]
- kvm-No-need-to-iterate-if-we-already-are-over-the-limit.patch [bz#513765 bz#589017]
- kvm-don-t-care-about-TLB-handling.patch [bz#513765 bz#589017]
- kvm-Fix-transferred-memory-calculation.patch [bz#513765 bz#589017]
- kvm-Maintaing-number-of-dirty-pages.patch [bz#513765 bz#589017]
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~224.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~224.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~224.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~224.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~224.0.1.el5", rls:"OracleLinux5"))) {
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
