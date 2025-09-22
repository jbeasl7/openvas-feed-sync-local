# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0095");
  script_cve_id("CVE-2023-4001", "CVE-2023-4692", "CVE-2023-4693", "CVE-2024-1048");
  script_tag(name:"creation_date", value:"2024-04-05 04:13:15 +0000 (Fri, 05 Apr 2024)");
  script_version("2024-04-05T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-04-05 05:05:37 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-01 19:03:42 +0000 (Wed, 01 Nov 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0095)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0095");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0095.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32997");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YSJAEGRR3XHMBBBKYOVMII4P34IXEYPE/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the MGASA-2024-0095 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds write flaw was found in grub2's NTFS filesystem driver.
This issue may allow an attacker to present a specially crafted NTFS
filesystem image, leading to grub's heap metadata corruption. In some
circumstances, the attack may also corrupt the UEFI firmware heap
metadata. As a result, arbitrary code execution and secure boot
protection bypass may be achieved. (CVE-2023-4692)
An out-of-bounds read flaw was found on grub2's NTFS filesystem driver.
This issue may allow a physically present attacker to present a
specially crafted NTFS file system image to read arbitrary memory
locations. A successful attack allows sensitive data cached in memory or
EFI variable values to be leaked, presenting a high Confidentiality
risk. (CVE-2023-4693)
An authentication bypass flaw was found in GRUB due to the way that GRUB
uses the UUID of a device to search for the configuration file that
contains the password hash for the GRUB password protection feature. An
attacker capable of attaching an external drive such as a USB stick
containing a file system with a duplicate UUID (the same as in the
'/boot/' file system) can bypass the GRUB password protection feature on
UEFI systems, which enumerate removable drives before non-removable
ones. (CVE-2023-4001)
A flaw was found in the grub2-set-bootflag utility of grub2. After the
fix of CVE-2019-14865, grub2-set-bootflag will create a temporary file
with the new grubenv content and rename it to the original grubenv file.
If the program is killed before the rename operation, the temporary file
will not be removed and may fill the filesystem when invoked multiple
times, resulting in a filesystem out of free inodes or blocks.
(CVE-2024-1048)");

  script_tag(name:"affected", value:"'grub2' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.06~28.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.06~28.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi", rpm:"grub2-efi~2.06~28.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-emu", rpm:"grub2-emu~2.06~28.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-emu-modules", rpm:"grub2-emu-modules~2.06~28.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-mageia-theme", rpm:"grub2-mageia-theme~2.06~28.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-uboot", rpm:"grub2-uboot~2.06~28.2.mga9", rls:"MAGEIA9"))) {
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
