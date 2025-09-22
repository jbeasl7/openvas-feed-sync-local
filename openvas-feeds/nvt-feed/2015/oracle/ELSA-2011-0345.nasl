# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122218");
  script_cve_id("CVE-2011-0011");
  script_tag(name:"creation_date", value:"2015-10-06 11:14:57 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-0345)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-0345");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-0345.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm' package(s) announced via the ELSA-2011-0345 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[qemu-kvm-0.12.1.2-2.113.el6_0.8]
- kvm-Revert-blockdev-Fix-drive_del-not-to-crash-when-driv.patch [bz#677170]
- kvm-Revert-blockdev-check-dinfo-ptr-before-using-v2.patch [bz#677170]
- kvm-Revert-Implement-drive_del-to-decouple-block-removal.patch [bz#677170]
- kvm-Revert-block-Catch-attempt-to-attach-multiple-device.patch [bz#677170]
- kvm-Revert-qdev-Decouple-qdev_prop_drive-from-DriveInfo-.patch [bz#677170]
- kvm-Revert-blockdev-Clean-up-automatic-drive-deletion-v2.patch [bz#677170]
- kvm-Revert-blockdev-New-drive_get_by_blockdev-v2.patch [bz#677170]
- kvm-Revert-qdev-Don-t-leak-string-property-value-on-hot-.patch [bz#677170]
- kvm-Revert-ide-Split-non-qdev-code-off-ide_init2.patch [bz#677170]
- kvm-Revert-ide-Change-ide_init_drive-to-require-valid-di.patch [bz#677170]
- kvm-Revert-ide-Split-ide_init1-off-ide_init2-v2.patch [bz#677170]
- kvm-Revert-ide-Remove-redundant-IDEState-member-conf.patch [bz#677170]
- Related: bz#677170
 (drive_del command to let libvirt safely remove block device from guest)

[qemu-kvm-0.12.1.2-2.113.el6_0.7]
- kvm-ide-Remove-redundant-IDEState-member-conf.patch [bz#677170]
- kvm-ide-Split-ide_init1-off-ide_init2-v2.patch [bz#677170]
- kvm-ide-Change-ide_init_drive-to-require-valid-dinfo-arg.patch [bz#677170]
- kvm-ide-Split-non-qdev-code-off-ide_init2.patch [bz#677170]
- kvm-qdev-Don-t-leak-string-property-value-on-hot-unplug.patch [bz#677170]
- kvm-blockdev-New-drive_get_by_blockdev-v2.patch [bz#677170]
- kvm-blockdev-Clean-up-automatic-drive-deletion-v2.patch [bz#677170]
- kvm-qdev-Decouple-qdev_prop_drive-from-DriveInfo-v2.patch [bz#677170]
- kvm-block-Catch-attempt-to-attach-multiple-devices-to-a-.patch [bz#677170]
- kvm-Implement-drive_del-to-decouple-block-removal-from-d.patch [bz#677170]
- kvm-blockdev-check-dinfo-ptr-before-using-v2.patch [bz#677170]
- kvm-blockdev-Fix-drive_del-not-to-crash-when-drive-is-no.patch [bz#677170]
- kvm-Fix-CVE-2011-0011-qemu-kvm-Setting-VNC-password-to-e.patch [bz#668598]
- Resolves: bz#668598
 (CVE-2011-0011 qemu-kvm: Setting VNC password to empty string silently disables all authentication [rhel-6.0.z])
- Resolves: bz#677170
 (drive_del command to let libvirt safely remove block device from guest)");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.113.el6_0.8", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.113.el6_0.8", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.113.el6_0.8", rls:"OracleLinux6"))) {
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
