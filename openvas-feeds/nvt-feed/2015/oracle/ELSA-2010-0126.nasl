# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122390");
  script_cve_id("CVE-2009-3722", "CVE-2010-0419");
  script_tag(name:"creation_date", value:"2015-10-06 11:18:04 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0126)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0126");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0126.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kvm' package(s) announced via the ELSA-2010-0126 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[kvm-83-105.0.1.el5_4.27]
- Add kvm-add-oracle-workaround-for-libvirt-bug.patch

[kvm-83-105.el5_4.27]
- kvm-kernel-KVM-VMX-Check-cpl-before-emulating-debug-register-ac.patch [bz#563516]
- Resolves: bz#563516
 (KVM: Check cpl before emulating debug register access [rhel-5.4.z])

[kvm-83-105.el5_4.26]
- kvm-kernel-KVM-Don-t-check-access-permission-when-loading-segme.patch [bz#563464]
- kvm-kernel-KVM-Disable-move-to-segment-registers-and-jump-far-i.patch [bz#563464]
- Resolves: bz#563464
 (EMBARGOED CVE-2010-0419 kvm: emulator privilege escalation segment selector check [rhel-5.4.z])

[kvm-83-105.el5_4.25]
- kvm-virtio-blk-Fix-reads-turned-into-writes-after-read-e.patch [bz#562776]
- kvm-virtio-blk-Handle-bdrv_aio_read-write-NULL-return.patch [bz#562776]
- Resolves: bz#562776
 (Guest image corruption after RHEV-H update to 5.4-2.1.3.el5_4rhev2_1)

[kvm-83-105.el5_4.24]
- Apply bz#561022 patches again (undo the reverts from kvm-83-105.el5_4.23)
- kvm-qemu-add-routines-for-atomic-16-bit-accesses-take-2.patch [bz#561022]
- kvm-qemu-virtio-atomic-access-for-index-values-take-2.patch [bz#561022]
- Resolves: bz#561022
 (QEMU terminates without warning with virtio-net and SMP enabled)

[kvm-83-105.el5_4.23]
- Revert bz#561022 patches by now, until they get better testing
- kvm-Revert-qemu-virtio-atomic-access-for-index-values.patch [bz#561022]
- kvm-Revert-qemu-add-routines-for-atomic-16-bit-accesses.patch [bz#561022]
- Related: bz#561022
 (QEMU terminates without warning with virtio-net and SMP enabled)");

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

  if(!isnull(res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~105.0.1.el5_4.27", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~105.0.1.el5_4.27", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~105.0.1.el5_4.27", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~105.0.1.el5_4.27", rls:"OracleLinux5"))) {
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
