# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122371");
  script_cve_id("CVE-2010-0430", "CVE-2010-0741");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:42 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0271)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0271");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0271.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2010-0271 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-164.0.1.el5]
- Add kvm-Introduce-oel-machine-type.patch
- Add kvm-add-oracle-workaround-for-libvirt-bug.patch

[kvm-83-164.el5]
- kvm-Fix-Windows-guests-SVVP-tests.patch [bz#495844]
- Resolves: bz#495844
 (KVM SVVP: 'Signed Driver check' failure - on the disabled vCPUs (that the VM's BIOS doesn't hide))

[kvm-83-163.el5]
- kvm-kernel-avoid-collision-between-out-of-sync-ksm-and-pci-pass.patch [bz#566385]
- Resolves: bz#566385
 (KVM host panic due to fault in paging64_sync_page() / panic occurs in connection with PCI passthru devices)

[kvm-83-162.el5]
- kvm-qemu-img-rebase-Add-f-option.patch [bz#569762]
- kvm-mark-PCI-IRQs-as-edge-triggered-in-mptables.patch [bz#536749]
- Resolves: bz#536749
 (can not boot rhel3.9 with if=virtio)
- Resolves: bz#569762
 ('qemu-img re-base' broken on block devices)
- Moved kver to 2.6.18-191.el5 to match build root

[kvm-83-161.el5]
- kvm-qemu-img-Fix-segfault-during-rebase.patch [bz#563141]
- Resolves: bz#563141
 (qemu-img re-base subcommand got Segmentation fault)
- Moved kver to 2.6.18-190.el5 to match build root

[kvm-83-160.el5]
- kvm-qxl-defer-vga-updates-in-case-commands-ring-is-full-.patch [bz#544785]
- Resolves: bz#544785
 (QEMU process can become non-responsive in case command are not pull from qxl vga ring)

[kvm-83-159.el5]
- Applied patch to spec file [bz#533453]
- Updated kversion to 2.6.18-189.el5 to match build root
- Resolves: bz#533453
 (kvm kmod package should require a compatible kernel version)

[kvm-83-158.el5]
- Updated kversion to 2.6.18-187.el5 to match build root
- kvm-kernel-KVM-Don-t-check-access-permission-when-loading-segme.patch [bz#563465]
- kvm-kernel-KVM-Disable-move-to-segment-registers-and-jump-far-i.patch [bz#563465]
- kvm-kernel-KVM-VMX-Check-cpl-before-emulating-debug-register-ac.patch [bz#563517]
- Resolves: bz#563465
 (EMBARGOED CVE-2010-0419 kvm: emulator privilege escalation segment selector check [rhel-5.5])
- Resolves: bz#563517
 (KVM: Check cpl before emulating debug register access [rhel-5.5])

[kvm-83-157.el5]
- kvm-CVE-2010-0297-usb-linux.c-fix-buffer-overflow.patch [bz#560770]
- Resolves: bz#560770
 (CVE-2010-0297 kvm-userspace-rhel5: usb-linux.c: fix buffer overflow [rhel-5.5])

[kvm-83-156.el5]
- kvm-kernel-KVM-PIT-control-word-is-write-only.patch [bz#553126]
- kvm-kernel-KVM-introduce-kvm_read_guest_virt-kvm_write_guest_vi.patch [bz#559095]
- kvm-kernel-KVM-remove-the-vmap-usage.patch [bz#559095]
- kvm-kernel-KVM-Use-kvm_-read-write-_guest_virt-to-read-and-writ.patch [bz#559095]
- kvm-kernel-KVM-fix-memory-access-during-x86-emulation.patch [bz#559095]
- kvm-kernel-Check-IOPL-level-during-io-instruction-emulation.patch [bz#560698]
- kvm-kernel-Fix-popf-emulation.patch [bz#560698]
- kvm-kernel-Check-CPL-level-during-privilege-instruction-emulati.patch [bz#560698]
- Resolves: bz#553126
 (CVE-2010-0309 kvm: cat /dev/port in guest cause the host hang [rhel-5.5])
- Resolves: bz#559095
 ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~164.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~164.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~164.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~164.0.1.el5", rls:"OracleLinux5"))) {
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
