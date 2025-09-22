# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122286");
  script_cve_id("CVE-2010-3881");
  script_tag(name:"creation_date", value:"2015-10-06 11:16:00 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2010-0998)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0998");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0998.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2010-0998 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-164.0.1.el5_5.30]
- Added kvm-add-oracle-workaround-for-libvirt-bug.patch to replace RHEL with OEL
- Added kvm-Introduce-oel-machine-type.patch so that OEL is a recognized VM

[kvm-83-164.el5_5.30]
- Revert the bz#661397 patches as they are not enough
 - kvm-kernel-Revert-KVM-VMX-Return-0-from-a-failed-VMREAD.patch [bz#661397]
 - kvm-kernel-Revert-KVM-Don-t-spin-on-virt-instruction-faults-dur.patch [bz#661397]
- Related: bz#661397
 (reboot(RB_AUTOBOOT) fails if kvm instance is running)
- kvm-kernel-KVM-fix-AMD-initial-TSC-offset-problems-additional-f.patch [bz#656984]
- Resolves: bz#656984
 (TSC offset of virtual machines is not initialized correctly by 'kvm_amd' kernel module.)

[kvm-83-164.el5_5.29]
- kvm-kernel-KVM-Don-t-spin-on-virt-instruction-faults-during-reb.patch [bz#661397]
- kvm-kernel-KVM-VMX-Return-0-from-a-failed-VMREAD.patch [bz#661397]
- Resolves: bz#661397
 (reboot(RB_AUTOBOOT) fails if kvm instance is running)

[kvm-83-164.el5_5.28]
- kvm-implement-dummy-PnP-support.patch [bz#659850]
- kvm-load-registers-after-restoring-pvclock-msrs.patch [bz#660239]
- Resolves: bz#659850
 (If VM boot seq. is set up as nc (PXE then disk) the VM is always stuck on trying to PXE boot)
- Resolves: bz#660239
 (clock drift when migrating a guest between mis-matched CPU clock speed)

[kvm-83-164.el5_5.27]
- kvm-kernel-KVM-fix-AMD-initial-TSC-offset-problems.patch [bz#656984]
- Resolves: bz#656984
 (TSC offset of virtual machines is not initialized correctly by 'kvm_amd' kernel module.)

[kvm-83-164.el5_5.26]
- Updated kversion to 2.6.18-194.26.1.el5 to match build root
- kvm-kernel-KVM-x86-fix-information-leak-to-userland.patch [bz#649832]
- Resolves: bz#649832
 (CVE-2010-3881 kvm: arch/x86/kvm/x86.c: reading uninitialized stack memory [5.5.z])
- CVE: CVE-2010-3881");

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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~164.0.1.el5_5.30", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~164.0.1.el5_5.30", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~164.0.1.el5_5.30", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~164.0.1.el5_5.30", rls:"OracleLinux5"))) {
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
