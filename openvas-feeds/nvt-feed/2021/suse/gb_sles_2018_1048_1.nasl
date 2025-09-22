# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1048.1");
  script_cve_id("CVE-2017-18257", "CVE-2018-1091", "CVE-2018-7740", "CVE-2018-8043", "CVE-2018-8822");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-20 15:05:20 +0000 (Fri, 20 Apr 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1048-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1048-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181048-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1019699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1022604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1046610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1060799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1073069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085679");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/802154");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-April/003954.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1048-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.126 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-1091: In the flush_tmregs_to_thread function in arch/powerpc/kernel/ptrace.c, a guest kernel crash can be triggered from unprivileged userspace during a core dump on a POWER host due to a missing processor feature check and an erroneous use of transactional memory (TM) instructions in the core dump path, leading to a denial of service (bnc#1087231).
- CVE-2018-7740: The resv_map_release function in mm/hugetlb.c allowed local users to cause a denial of service (BUG) via a crafted application that made mmap system calls and has a large pgoff argument to the remap_file_pages system call (bnc#1084353).
- CVE-2018-8043: The unimac_mdio_probe function in drivers/net/phy/mdio-bcm-unimac.c did not validate certain resource availability, which allowed local users to cause a denial of service (NULL pointer dereference) (bnc#1084829).
- CVE-2017-18257: The __get_data_block function in fs/f2fs/data.c allowed local users to cause a denial of service (integer overflow and loop) via crafted use of the open and fallocate system calls with an FS_IOC_FIEMAP ioctl. (bnc#1088241)
- CVE-2018-8822: Incorrect buffer length handling in the ncp_read_kernel function in fs/ncpfs/ncplib_kernel.c could be exploited by malicious NCPFS servers to crash the kernel or execute code (bnc#1086162).


The following non-security bugs were fixed:

- acpica: Add header support for TPM2 table changes (bsc#1084452).
- acpica: Add support for new SRAT subtable (bsc#1085981).
- acpica: iasl: Update to IORT SMMUv3 disassembling (bsc#1085981).
- acpi/iort: numa: Add numa node mapping for smmuv3 devices (bsc#1085981).
- acpi, numa: fix pxm to online numa node associations (bnc#1012382).
- acpi / pmic: xpower: Fix power_table addresses (bnc#1012382).
- acpi/processor: Fix error handling in __acpi_processor_start() (bnc#1012382).
- acpi/processor: Replace racy task affinity logic (bnc#1012382).
- add mainline tag to various patches to be able to get further work done
- af_iucv: enable control sends in case of SEND_SHUTDOWN (bnc#1085507, LTC#165135).
- agp/intel: Flush all chipset writes after updating the GGTT (bnc#1012382).
- ahci: Add PCI-id for the Highpoint Rocketraid 644L card (bnc#1012382).
- alsa: aloop: Fix access to not-yet-ready substream via cable (bnc#1012382).
- alsa: aloop: Sync stale timer before release (bnc#1012382).
- alsa: firewire-digi00x: handle all MIDI messages on streaming packets (bnc#1012382).
- alsa: hda: Add a power_save blacklist (bnc#1012382).
- alsa: hda: add dock and led support for HP EliteBook 820 G3 (bnc#1012382).
- alsa: hda: add dock and led support for HP ProBook 640 G2 (bnc#1012382).
- alsa: hda/realtek - Always immediately update mute LED with pin VREF (bnc#1012382).
- alsa: hda/realtek - Fix dock line-out volume on Dell ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.126~94.22.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.126~94.22.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.126~94.22.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.4.126~94.22.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.126~94.22.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.126~94.22.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.126~94.22.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.126~94.22.1", rls:"SLES12.0SP3"))) {
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
