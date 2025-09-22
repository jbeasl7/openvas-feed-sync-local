# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123397");
  script_cve_id("CVE-2013-4148", "CVE-2013-4151", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0182", "CVE-2014-2894", "CVE-2014-3461");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:16 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 14:39:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Oracle: Security Advisory (ELSA-2014-0743)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0743");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0743.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2014-0743 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.12.1.2-2.415.el6_5.10]
- kvm-virtio-out-of-bounds-buffer-write-on-invalid-state-l.patch [bz#1095692]
- kvm-usb-sanity-check-setup_index-setup_len-in-post_load.patch [bz#1095743]
- kvm-usb-sanity-check-setup_index-setup_len-in-post_load-2.patch [bz#1095743]
- kvm-virtio-scsi-fix-buffer-overrun-on-invalid-state-load.patch [bz#1095739]
- kvm-virtio-avoid-buffer-overrun-on-incoming-migration.patch [bz#1095735]
- kvm-virtio-validate-num_sg-when-mapping.patch [bz#1095763 bz#1096124]
- kvm-virtio-allow-mapping-up-to-max-queue-size.patch [bz#1095763 bz#1096124]
- kvm-enable-PCI-multiple-segments-for-pass-through-device.patch [bz#1099941]
- kvm-virtio-net-fix-buffer-overflow-on-invalid-state-load.patch [bz#1095675]
- kvm-virtio-validate-config_len-on-load.patch [bz#1095779]
- kvm-usb-fix-up-post-load-checks.patch [bz#1096825]
- kvm-CPU-hotplug-use-apic_id_for_cpu-round-2-RHEL-6-only.patch [bz#1100575]
- Resolves: bz#1095675
 ()
- Resolves: bz#1095692
 ()
- Resolves: bz#1095735
 ()
- Resolves: bz#1095739
 ()
- Resolves: bz#1095743
 ()
- Resolves: bz#1095763
 ()
- Resolves: bz#1095779
 ()
- Resolves: bz#1096124
 ()
- Resolves: bz#1096825
 ()
- Resolves: bz#1099941
 ()
- Resolves: bz#1100575
 (Some vCPU topologies not accepted by libvirt)

[0.12.1.2-2.415.el6_5.9]
- kvm-ide-Correct-improper-smart-self-test-counter-reset-i.patch [bz#1087978]
- Resolves: bz#1087978
 (CVE-2014-2894 qemu-kvm: QEMU: out of bounds buffer accesses, guest triggerable via IDE SMART [rhel-6.5.z])");

  script_tag(name:"affected", value:"'qemu-kvm' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.415.el6_5.10", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.415.el6_5.10", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.415.el6_5.10", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.415.el6_5.10", rls:"OracleLinux6"))) {
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
