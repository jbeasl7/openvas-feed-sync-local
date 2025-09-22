# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2822.1");
  script_cve_id("CVE-2023-1077", "CVE-2023-1079", "CVE-2023-1249", "CVE-2023-1637", "CVE-2023-2002", "CVE-2023-3090", "CVE-2023-3111", "CVE-2023-3141", "CVE-2023-3159", "CVE-2023-3161", "CVE-2023-3268", "CVE-2023-3358", "CVE-2023-35824");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-09 22:51:48 +0000 (Fri, 09 Jun 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2822-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2822-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232822-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1160435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190317");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212165");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212938");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-July/015490.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2822-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2023-3090: Fixed a heap out-of-bounds write in the ipvlan network driver (bsc#1212842).
- CVE-2023-3111: Fixed a use-after-free vulnerability in prepare_to_relocate in fs/btrfs/relocation.c (bsc#1212051).
- CVE-2023-3358: Fixed a NULL pointer dereference flaw in the Integrated Sensor Hub (ISH) driver (bsc#1212606).
- CVE-2023-1249: Fixed a use-after-free flaw in the core dump subsystem that allowed a local user to crash the system (bsc#1209039).
- CVE-2023-3268: Fixed an out of bounds (OOB) memory access flaw in relay_file_read_start_pos in kernel/relay.c (bsc#1212502).
- CVE-2023-2002: Fixed a flaw that allowed an attacker to unauthorized execution of management commands, compromising the confidentiality, integrity, and availability of Bluetooth communication (bsc#1210533).
- CVE-2023-35824: Fixed a use-after-free in dm1105_remove in drivers/media/pci/dm1105/dm1105.c (bsc#1212501).
- CVE-2023-3161: Fixed shift-out-of-bounds in fbcon_set_font() (bsc#1212154).
- CVE-2023-3141: Fixed a use-after-free flaw in r592_remove in drivers/memstick/host/r592.c, that allowed local attackers to crash the system at device disconnect (bsc#1212129).
- CVE-2023-3159: Fixed use-after-free issue in driver/firewire in outbound_phy_packet_callback (bsc#1212128).
- CVE-2023-1077: Fixed a type confusion in pick_next_rt_entity(), that could cause memory corruption (bsc#1208600).
- CVE-2023-1637: Fixed vulnerability that could lead to unauthorized access to CPU memory after resuming CPU from suspend-to-RAM (bsc#1209779).
- CVE-2023-1079: Fixed a use-after-free problem that could have been triggered in asus_kbd_backlight_set when plugging/disconnecting a malicious USB device (bsc#1208604).

The following non-security bugs were fixed:

- Decrease the number of SMB3 smbdirect client SGEs (bsc#1190317).
- Drop dvb-core fix patch due to bug (bsc#1205758).
- Fix formatting of client smbdirect RDMA logging (bsc#1190317).
- Fix missing top level chapter numbers on SLE12 SP5 (bsc#1212158).
- Fix usrmerge error (boo#1211796).
- Handle variable number of SGEs in client smbdirect send (bsc#1190317).
- Reduce client smbdirect max receive segment size (bsc#1190317).
- Remove usrmerge compatibility symlink in buildroot (boo#1211796)
- affs: initialize fsdata in affs_truncate() (git-fixes).
- bnx2x: Check if transceiver implements DDM before access (git-fixes).
- bnxt_en: Fix mqprio and XDP ring checking logic (git-fixes).
- bnxt_en: Fix typo in PCI id to device description string mapping (git-fixes).
- bnxt_en: Query default VLAN before VNIC setup on a VF (git-fixes).
- bnxt_en: Remove debugfs when pci_register_driver failed (git-fixes).
- bnxt_en: fix NQ resource accounting during vf creation on 57500 chips (git-fixes).
- bnxt_en: fix potentially incorrect return value ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.165.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.165.1", rls:"SLES12.0SP5"))) {
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
