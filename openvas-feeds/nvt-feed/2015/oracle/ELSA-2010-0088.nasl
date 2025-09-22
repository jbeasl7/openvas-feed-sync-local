# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122395");
  script_cve_id("CVE-2010-0297", "CVE-2010-0298", "CVE-2010-0306", "CVE-2010-0309");
  script_tag(name:"creation_date", value:"2015-10-06 11:18:12 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0088)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0088");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0088.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2010-0088 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-105.0.1.el5_4.22]
- Add kvm-add-oracle-workaround-for-libvirt-bug.patch

[kvm-83-105.el5_4.22]
- kvm-CVE-2010-0297-usb-linux.c-fix-buffer-overflow.patch [bz#560769]
- Resolves: bz#560769
 (CVE-2010-0297 kvm-userspace-rhel5: usb-linux.c: fix buffer overflow [rhel-5.4.z])

[kvm-83-105.el5_4.21]
- kvm-kernel-KVM-introduce-kvm_read_guest_virt-kvm_write_guest_vi.patch [bz#559093]
- kvm-kernel-KVM-remove-the-vmap-usage.patch [bz#559093]
- kvm-kernel-KVM-Use-kvm_-read-write-_guest_virt-to-read-and-writ.patch [bz#559093]
- kvm-kernel-KVM-fix-memory-access-during-x86-emulation.patch [bz#559093]
- kvm-kernel-Check-IOPL-level-during-io-instruction-emulation.patch [bz#560697]
- kvm-kernel-Fix-popf-emulation.patch [bz#560697]
- kvm-kernel-Check-CPL-level-during-privilege-instruction-emulati.patch [bz#560697]
- kvm-kernel-KVM-PIT-control-word-is-write-only.patch [bz#560888]
- Resolves: bz#559093
 (EMBARGOED CVE-2010-0298 kvm: emulator privilege escalation [rhel-5.4.z])
- Resolves: bz#560697
 (EMBARGOED CVE-2010-0306 kvm: emulator privilege escalation IOPL/CPL level check [rhel-5.4.z])
- Resolves: bz#560888
 (CVE-2010-0309 kvm: cat /dev/port in guest cause the host hang [rhel-5.4.z])

[kvm-83-105.el5_4.20]
- Updated kversion to 2.6.18-164.11.1.el5 to match build root
- kvm-qemu-add-routines-for-atomic-16-bit-accesses.patch [bz#561022]
- kvm-qemu-virtio-atomic-access-for-index-values.patch [bz#561022]
- Resolves: bz#561022
 (QEMU terminates without warning with virtio-net and SMP enabled)

[kvm-83-105.el5_4.19]
- Updated kversion to 2.6.18-164.10.1.el5 to match build root
- kvm-Fix-VDI-audio-stop.patch [bz#552519]
- Resolves: bz#552519
 (KVM : QEMU-Audio attempting to stop unactivated audio device (snd_playback_stop: ASSERT playback_channel->base.active failed).)

[kvm-83-105.el5_4.18]
- kvm-Fix-a-race-in-the-device-that-cuased-guest-stack-on-.patch [bz#553249]
- Resolves: bz#553249
 (hypercall device - Vm becomes non responsive on Sysmark benchmark (when more than 7 vm's running simultaneously))

[kvm-83-105.el5_4.17]
- kvm-kernel-KVM-x86-make-double-triple-fault-promotion-generic-t.patch [bz#552518]
- kvm-kernel-KVM-x86-raise-TSS-exception-for-NULL-CS-and-SS-segme.patch [bz#552518]
- Resolves: bz#552518
 (Rhev-Block driver causes 'unhandled vm exit' with 32bit win2k3r2sp2 Guest VM on restart)
- kvm-RHEL-5.X-5.4.Z-Makefile-fix-ksm-dir-has-no-ARCH-pref.patch [bz#552530]
- Resolves: bz#552530
 (Build tree for RHEL 5.X and RHEL 5.4.z contains build bugs)

[kvm-83-105.el5_4.16]
- kvm-savevm-add-version_id-to-all-savevm-functions.patch [bz#552529]
- kvm-We-need-current-machine-defined-sooner.patch [bz#552529]
- kvm-Add-support-for-DeviceVersion-to-machine-type.patch [bz#552529]
- kvm-Add-machine-name-alias-support.patch [bz#552529]
- kvm-Introduce-rhel5.4.0-machine-type.patch [bz#552529]
- kvm-Introduce-rhel-5.4.4-machine-type.patch [bz#552529]
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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~105.0.1.el5_4.22", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~105.0.1.el5_4.22", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~105.0.1.el5_4.22", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~105.0.1.el5_4.22", rls:"OracleLinux5"))) {
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
