# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123533");
  script_cve_id("CVE-2013-4344");
  script_tag(name:"creation_date", value:"2015-10-06 11:05:10 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-1553)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-1553");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-1553.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2013-1553 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[qemu-kvm-0.12.1.2-2.415.el6]
- kvm-target-i386-don-t-migrate-steal-time-MSR-on-older-ma.patch [bz#1022821]
- Resolves: bz#1022821
 (live-migration from RHEL6.5 to RHEL6.4.z fails with 'error while loading state for instance 0x0 of device 'cpu'')

[0.12.1.2-2.414.el6]
- kvm-vmstate-Add-max_version_id-field-to-VMStateDescripti.patch [bz#1016736]
- kvm-savevm-Introduce-max_version_id-field-to-SaveStateEn.patch [bz#1016736]
- kvm-i386-Set-cpu-section-version_id-to-11.patch [bz#1016736]
- kvm-qemu-ga-execute-fsfreeze-freeze-in-reverse-order-of-.patch [bz#1015633]
- Resolves: bz#1015633
 (qemu-guest-agent: 'guest-fsfreeze-freeze' deadlocks if the guest have mounted disk images)
- Resolves: bz#1016736
 (CPU migration data has version_id 12 but version 11 format)

[0.12.1.2-2.413.el6]
- kvm-scsi-Allocate-SCSITargetReq-r-buf-dynamically-CVE-20.patch [bz#1007330]
- kvm-scsi-Fix-data-length-SCSI_SENSE_BUF_SIZE.patch [bz#956929]
- Resolves: bz#1007330
 (CVE-2013-4344 qemu: buffer overflow in scsi_target_emulate_report_luns)
- Resolves: bz#956929
 (/usr/libexec/qemu-kvm was killed by signal 6 (SIGABRT) when SCSI inquiry is sent to unsupported page inside the KVM guest)

[qemu-kvm-0.12.1.2-2.412.el6]
- kvm-char-move-backends-io-watch-tag-to-CharDriverState.patch [bz#985205]
- kvm-char-use-common-function-to-disable-callbacks-on-cha.patch [bz#985205]
- kvm-char-remove-watch-callback-on-chardev-detach-from-fr.patch [bz#985205]
- kvm-os-posix-block-SIGUSR2-in-os_setup_early_signal_hand.patch [bz#996814]
- Resolves: bz#985205
 (QEMU core dumped when do hot-unplug virtio serial port during transfer file between host to guest with virtio serial through TCP socket)
- Resolves: bz#996814
 (boot image with gluster native mode can't work with attach another device from local file system)

[qemu-kvm-0.12.1.2-2.411.el6]
- kvm-block-don-t-lose-data-from-last-incomplete-sector.patch [bz#1009370]
- kvm-vmdk-fix-cluster-size-check-for-flat-extents.patch [bz#1009370]
- Resolves: bz#1009370
 (qemu-img refuses to open the vmdk format image its created)

[qemu-kvm-0.12.1.2-2.410.el6]
- kvm-chardev-fix-pty_chr_timer.patch [bz#995341]
- Resolves: bz#995341
 (hot-unplug chardev with pty backend caused qemu Segmentation fault)

[qemu-kvm-0.12.1.2-2.409.el6]
- kvm-exec-Simplify-allocation-of-guest-RAM.patch [bz#867921]
- kvm-exec-Don-t-abort-when-we-can-t-allocate-guest-memory.patch [bz#867921]
- kvm-block-better-error-message-for-read-only-format-name.patch [bz#999788]
- kvm-vmdk-Add-migration-blocker.patch [bz#999358]
- kvm-scsi-Fix-scsi_bus_legacy_add_drive-scsi-generic-with.patch [bz#1013478]
- kvm-Add-support-for-JSON-pretty-printing.patch [bz#1010610]
- kvm-qemu-img-add-dirty-flag-status.patch [bz#1010610]
- kvm-qemu-img-make-info-backing-file-output-correct-and-e2.patch [bz#1010610]
- kvm-qapi-Add-SnapshotInfo-and-ImageInfo.patch [bz#1010610]
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.415.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.415.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.415.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.415.el6", rls:"OracleLinux6"))) {
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
