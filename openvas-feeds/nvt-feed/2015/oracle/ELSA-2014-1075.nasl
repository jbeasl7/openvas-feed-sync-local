# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123329");
  script_cve_id("CVE-2014-0222", "CVE-2014-0223");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:21 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1075)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1075");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1075.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2014-1075 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.12.1.2-2.415.el6_5.14]
- The commit for zrelease .13 was incomplete, the changes to qemu-kvm.spec
 did not include the '%patchNNNN -p1' lines for patches 4647 through 4655,
 so although the patch files themselves were committed, the srpm build
 did not pick them up. In addition, the commit log did not describe the
 patches.

 This commit corrects these problems and bumps the zrelease to .14.

[0.12.1.2-2.415.el6_5.13]
- kvm-block-Create-proper-size-file-for-disk-mirror.patch [bz#1109715]
- kvm-block-Fix-bdrv_is_allocated-return-value.patch [bz#1109715]
- kvm-scsi-bus-prepare-scsi_req_new-for-introduction-of-pars.patch [bz#1125131]
- kvm-scsi-bus-introduce-parse_cdb-in-SCSIDeviceClass-and-SC.patch [bz#1125131]
- kvm-scsi-block-extract-scsi_block_is_passthrough.patch [bz#1125131]
- kvm-scsi-block-scsi-generic-implement-parse_cdb.patch [bz#1125131]
- kvm-virtio-scsi-implement-parse_cdb.patch [bz#1125131]
- kvm-virtio-scsi-Fix-reset-callback-for-virtio-scsi.patch [bz#1123271]
- kvm-virtio-scsi-add-ioeventfd-support.patch [bz#1123271]
- Resolves: bz#1109715
 (live incremental migration of vm with common shared base, size(disk) > size(base) transfers unallocated sectors, explodes disk on dest)
- Resolves: bz#1123271
 (Enable ioenventfd for virtio-scsi-pci)
- Resolves: bz#1125131
 ([FJ6.5 Bug] SCSI command issued from KVM guest doesn't reach target device)

[0.12.1.2-2.415.el6_5.12]
- kvm-qcow-Return-real-error-code-in-qcow_open.txt [bz#1097225]
- kvm-qcow1-Make-padding-in-the-header-explicit.txt [bz#1097225]
- kvm-qcow1-Check-maximum-cluster-size.txt [bz#1097225]
- kvm-qcow1-Validate-L2-table-size-CVE-2014-0222.txt [bz#1097225]
- kvm-qcow1-Validate-image-size-CVE-2014-0223.txt [bz#1097234]
- kvm-qcow1-Stricter-backing-file-length-check.txt [bz#1097234]
- Resolves: bz#1097225
 (CVE-2014-0222 qemu-kvm: Qemu: qcow1: validate L2 table size to avoid integer overflows [rhel-6.5.z])
- Resolves: bz#1097234
 (CVE-2014-0223 qemu-kvm: Qemu: qcow1: validate image size to avoid out-of-bounds memory access [rhel-6.5.z])

[0.12.1.2-2.415.el6_5.11]
- kvm-block-Fix-bdrv_is_allocated-for-short-backing-files.patch [bz#1109715]
- Resolves: bz#1109715
 (live incremental migration of vm with common shared base, size(disk) > size(base) transfers unallocated sectors, explodes disk on dest)");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~0.12.1.2~2.415.el6_5.14", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.415.el6_5.14", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.415.el6_5.14", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.415.el6_5.14", rls:"OracleLinux6"))) {
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
