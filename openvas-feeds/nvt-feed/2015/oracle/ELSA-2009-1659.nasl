# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122409");
  script_cve_id("CVE-2009-4031");
  script_tag(name:"creation_date", value:"2015-10-08 11:44:48 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-1659)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1659");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1659.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2009-1659 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-105.0.1.el5_4.13]
- Add kvm-add-oracle-workaround-for-libvirt-bug.patch

[kvm-83-105.el5_4.13]
- kvm-kernel-KVM-x86-emulator-limit-instructions-to-15-bytes.patch [bz#541164]
- Resolves: bz#541164
 (CVE-2009-4031 kernel: KVM: x86 emulator: limit instructions to 15 bytes [rhel-5.4.z])

[kvm-83-105.el5_4.12]
- kvm-virtio-blk-Stop-VM-on-read-errors.patch [bz#537334]
- kvm-ide-Stop-VM-on-read-errors-respin.patch [bz#537334 bz#540406]
- Resolves: bz#537334
 (O/S Filesystem Corruption with RHEL-5.4 on a RHEV Guest)
- Resolves: bz#540406
 (RHEL5.4 VM image corruption with an IDE v-disk)

[kvm-83-105.el5_4.11]
- kvm-qcow2-Refactor-update_refcount-take-2.patch [bz#520693]
- kvm-qcow2-Update-multiple-refcounts-at-once-take-2.patch [bz#520693]
- kvm-Combined-patch-of-two-upstream-commits-the-second-fi-take-2.patch.patch [bz#520693]
- kvm-alloc_cluster_link_l2-Write-complete-sectors-take-2.patch.patch [bz#520693]
- kvm-update_refcount-Write-complete-sectors-take-2.patch [bz#520693]
- Resolves: bz#520693
 (Bad qcow2 performance with cache=off)

[kvm-83-105.el5_4.10]
- Update kversion to 2.6.18-164.6.1.el5 to match build root
- kvm-kernel-get_tss_base_addr-should-return-gpa_t-type.patch [bz#532043]
- kvm-kernel-KVM-VMX-Adjust-rflags-if-in-real-mode-emulation.patch [bz#532031]
- kvm-kernel-KVM-When-switching-to-a-vm8086-task-load-segments-as.patch [bz#532031]
- kvm-kernel-KVM-Fix-task-switch-back-link-handling-v2-including-.patch [bz#532031]
- Resolves: bz#532031
 (KVM does not implement proper support for hardware task linking when using vm8086 mode)
- Resolves: bz#532043
 (qemu aborted when restart 32bitwin23k with more than 4G mem in intel host.)");

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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~105.0.1.el5_4.13", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~105.0.1.el5_4.13", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~105.0.1.el5_4.13", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~105.0.1.el5_4.13", rls:"OracleLinux5"))) {
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
