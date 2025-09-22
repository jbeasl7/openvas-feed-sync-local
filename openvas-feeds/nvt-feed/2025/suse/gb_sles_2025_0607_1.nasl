# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0607.1");
  script_cve_id("CVE-2024-45774", "CVE-2024-45775", "CVE-2024-45776", "CVE-2024-45777", "CVE-2024-45778", "CVE-2024-45779", "CVE-2024-45780", "CVE-2024-45781", "CVE-2024-45782", "CVE-2024-45783", "CVE-2024-56737", "CVE-2025-0622", "CVE-2025-0624", "CVE-2025-0677", "CVE-2025-0678", "CVE-2025-0684", "CVE-2025-0685", "CVE-2025-0686", "CVE-2025-0689", "CVE-2025-0690", "CVE-2025-1118", "CVE-2025-1125");
  script_tag(name:"creation_date", value:"2025-02-24 04:07:27 +0000 (Mon, 24 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-07 20:42:19 +0000 (Fri, 07 Mar 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0607-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0607-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250607-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236316");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237014");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-February/020379.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2' package(s) announced via the SUSE-SU-2025:0607-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grub2 fixes the following issues:

- CVE-2024-45781: Fixed strcpy overflow in ufs. (bsc#1233617)
- CVE-2024-56737: Fixed a heap-based buffer overflow in hfs. (bsc#1234958)
- CVE-2024-45782: Fixed strcpy overflow in hfs. (bsc#1233615)
- CVE-2024-45780: Fixed an overflow in tar/cpio. (bsc#1233614)
- CVE-2024-45783: Fixed a refcount overflow in hfsplus. (bsc#1233616)
- CVE-2024-45774: Fixed a heap overflow in JPEG parser. (bsc#1233609)
- CVE-2024-45775: Fixed a missing NULL check in extcmd parser. (bsc#1233610)
- CVE-2024-45776: Fixed an overflow in .MO file handling. (bsc#1233612)
- CVE-2024-45777: Fixed an integer overflow in gettext. (bsc#1233613)
- CVE-2024-45778: Fixed bfs filesystem by removing it from lockdown capable modules. (bsc#1233606)
- CVE-2024-45779: Fixed a heap overflow in bfs. (bsc#1233608)
- CVE-2025-0624: Fixed an out-of-bounds write during the network boot process. (bsc#1236316)
- CVE-2025-0622: Fixed a use-after-free when handling hooks during module unload in command/gpg . (bsc#1236317)
- CVE-2025-0690: Fixed an integer overflow that may lead to an out-of-bounds write through the read command.
 (bsc#1237012)
- CVE-2025-1118: Fixed an issue where the dump command was not being blocked when grub was in lockdown mode.
 (bsc#1237013)
- CVE-2025-0677: Fixed an integer overflow that may lead to an out-of-bounds write when handling symlinks in ufs.
 (bsc#1237002)
- CVE-2025-0684: Fixed an integer overflow that may lead to an out-of-bounds write when handling symlinks in reiserfs.
 (bsc#1237008)
- CVE-2025-0685: Fixed an integer overflow that may lead to an out-of-bounds write when handling symlinks in jfs.
 (bsc#1237009)
- CVE-2025-0686: Fixed an integer overflow that may lead to an out-of-bounds write when handling symlinks in romfs.
 (bsc#1237010)
- CVE-2025-0689: Fixed a heap-based buffer overflow in udf that may lead to arbitrary code execution. (bsc#1237011)
- CVE-2025-1125: Fixed an integer overflow that may lead to an out-of-bounds write in hfs. (bsc#1237014)
- CVE-2025-0678: Fixed an integer overflow that may lead to an out-of-bounds write in squash4. (bsc#1237006)");

  script_tag(name:"affected", value:"'grub2' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"grub2", rpm:"grub2~2.04~150300.22.52.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-arm64-efi", rpm:"grub2-arm64-efi~2.04~150300.22.52.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-i386-pc", rpm:"grub2-i386-pc~2.04~150300.22.52.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-powerpc-ieee1275", rpm:"grub2-powerpc-ieee1275~2.04~150300.22.52.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-s390x-emu", rpm:"grub2-s390x-emu~2.04~150300.22.52.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-snapper-plugin", rpm:"grub2-snapper-plugin~2.04~150300.22.52.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-systemd-sleep-plugin", rpm:"grub2-systemd-sleep-plugin~2.04~150300.22.52.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-efi", rpm:"grub2-x86_64-efi~2.04~150300.22.52.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-x86_64-xen", rpm:"grub2-x86_64-xen~2.04~150300.22.52.3", rls:"SLES15.0SP3"))) {
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
