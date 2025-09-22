# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0188");
  script_cve_id("CVE-2025-6019");
  script_tag(name:"creation_date", value:"2025-06-25 04:13:45 +0000 (Wed, 25 Jun 2025)");
  script_version("2025-06-26T05:40:52+0000");
  script_tag(name:"last_modification", value:"2025-06-26 05:40:52 +0000 (Thu, 26 Jun 2025)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-19 12:15:19 +0000 (Thu, 19 Jun 2025)");

  script_name("Mageia: Security Advisory (MGASA-2025-0188)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0188");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0188.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=34380");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2025/06/17/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libblockdev, udisks2' package(s) announced via the MGASA-2025-0188 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A Local Privilege Escalation (LPE) vulnerability was found in
libblockdev. Generally, the 'allow_active' setting in Polkit permits a
physically present user to take certain actions based on the session
type. Due to the way libblockdev interacts with the udisks daemon, an
'allow_active' user on a system may be able escalate to full root
privileges on the target host. Normally, udisks mounts user-provided
filesystem images with security flags like nosuid and nodev to prevent
privilege escalation. However, a local attacker can create a specially
crafted XFS image containing a SUID-root shell, then trick udisks into
resizing it. This mounts their malicious filesystem with root
privileges, allowing them to execute their SUID-root shell and gain
complete control of the system.");

  script_tag(name:"affected", value:"'libblockdev, udisks2' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_btrfs-devel", rpm:"lib64bd_btrfs-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_btrfs3", rpm:"lib64bd_btrfs3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_crypto-devel", rpm:"lib64bd_crypto-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_crypto3", rpm:"lib64bd_crypto3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_dm-devel", rpm:"lib64bd_dm-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_dm3", rpm:"lib64bd_dm3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_fs-devel", rpm:"lib64bd_fs-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_fs3", rpm:"lib64bd_fs3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_loop-devel", rpm:"lib64bd_loop-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_loop3", rpm:"lib64bd_loop3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_lvm-dbus-devel", rpm:"lib64bd_lvm-dbus-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_lvm-dbus3", rpm:"lib64bd_lvm-dbus3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_lvm-devel", rpm:"lib64bd_lvm-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_lvm3", rpm:"lib64bd_lvm3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_mdraid-devel", rpm:"lib64bd_mdraid-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_mdraid3", rpm:"lib64bd_mdraid3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_mpath-devel", rpm:"lib64bd_mpath-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_mpath3", rpm:"lib64bd_mpath3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_nvdimm-devel", rpm:"lib64bd_nvdimm-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_nvdimm3", rpm:"lib64bd_nvdimm3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_nvme-devel", rpm:"lib64bd_nvme-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_nvme3", rpm:"lib64bd_nvme3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_part-devel", rpm:"lib64bd_part-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_part3", rpm:"lib64bd_part3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_smart-devel", rpm:"lib64bd_smart-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_smart3", rpm:"lib64bd_smart3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_smartmontools3", rpm:"lib64bd_smartmontools3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_swap-devel", rpm:"lib64bd_swap-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_swap3", rpm:"lib64bd_swap3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_utils-devel", rpm:"lib64bd_utils-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bd_utils3", rpm:"lib64bd_utils3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64blockdev-devel", rpm:"lib64blockdev-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64blockdev-gir3.0", rpm:"lib64blockdev-gir3.0~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64blockdev3", rpm:"lib64blockdev3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64udisks-gir2.0", rpm:"lib64udisks-gir2.0~2.10.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64udisks2-devel", rpm:"lib64udisks2-devel~2.10.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64udisks2_0", rpm:"lib64udisks2_0~2.10.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_btrfs-devel", rpm:"libbd_btrfs-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_btrfs3", rpm:"libbd_btrfs3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_crypto-devel", rpm:"libbd_crypto-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_crypto3", rpm:"libbd_crypto3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_dm-devel", rpm:"libbd_dm-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_dm3", rpm:"libbd_dm3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_fs-devel", rpm:"libbd_fs-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_fs3", rpm:"libbd_fs3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_loop-devel", rpm:"libbd_loop-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_loop3", rpm:"libbd_loop3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_lvm-dbus-devel", rpm:"libbd_lvm-dbus-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_lvm-dbus3", rpm:"libbd_lvm-dbus3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_lvm-devel", rpm:"libbd_lvm-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_lvm3", rpm:"libbd_lvm3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_mdraid-devel", rpm:"libbd_mdraid-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_mdraid3", rpm:"libbd_mdraid3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_mpath-devel", rpm:"libbd_mpath-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_mpath3", rpm:"libbd_mpath3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_nvdimm-devel", rpm:"libbd_nvdimm-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_nvdimm3", rpm:"libbd_nvdimm3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_nvme-devel", rpm:"libbd_nvme-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_nvme3", rpm:"libbd_nvme3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_part-devel", rpm:"libbd_part-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_part3", rpm:"libbd_part3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_smart-devel", rpm:"libbd_smart-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_smart3", rpm:"libbd_smart3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_smartmontools3", rpm:"libbd_smartmontools3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_swap-devel", rpm:"libbd_swap-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_swap3", rpm:"libbd_swap3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_utils-devel", rpm:"libbd_utils-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbd_utils3", rpm:"libbd_utils3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev", rpm:"libblockdev~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-devel", rpm:"libblockdev-devel~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-gir3.0", rpm:"libblockdev-gir3.0~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-plugins-all", rpm:"libblockdev-plugins-all~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev-tools", rpm:"libblockdev-tools~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libblockdev3", rpm:"libblockdev3~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks-gir2.0", rpm:"libudisks-gir2.0~2.10.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-devel", rpm:"libudisks2-devel~2.10.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2_0", rpm:"libudisks2_0~2.10.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-blockdev", rpm:"python3-blockdev~3.3.1~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2", rpm:"udisks2~2.10.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-btrfs", rpm:"udisks2-btrfs~2.10.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-lsm", rpm:"udisks2-lsm~2.10.1~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-lvm2", rpm:"udisks2-lvm2~2.10.1~1.1.mga9", rls:"MAGEIA9"))) {
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
