# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0901.1");
  script_cve_id("CVE-2017-18249", "CVE-2019-2024", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-9213");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:45 +0000 (Tue, 05 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0901-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0901-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190901-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1020413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1031492");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1042286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1075697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087036");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1116653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121726");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1121805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1125892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126389");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1126805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127561");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128756");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129923");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-April/005309.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0901-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 Azure kernel was updated to 4.4.176 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2019-2024: A use-after-free when disconnecting a source was fixed which could lead to crashes. bnc#1129179).
- CVE-2019-9213: expand_downwards in mm/mmap.c lacked a check for the mmap minimum address, which made it easier for attackers to exploit kernel NULL pointer dereferences on non-SMAP platforms. This is related to a capability check for the wrong task (bnc#1128166).
- CVE-2019-6974: kvm_ioctl_create_device in virt/kvm/kvm_main.c mishandled reference counting because of a race condition, leading to a use-after-free. (bnc#1124728)
- CVE-2019-3459, CVE-2019-3460: The Bluetooth stack suffered from two remote information leak vulnerabilities in the code that handles incoming L2cap configuration packets (bsc#1120758).
- CVE-2019-7221: Fixed a use-after-free vulnerability in the KVM hypervisor related to the emulation of a preemption timer, allowing an guest user/process to crash the host kernel. (bsc#1124732).
- CVE-2019-7222: Fixed an information leakage in the KVM hypervisor related to handling page fault exceptions, which allowed a guest user/process to use this flaw to leak the host's stack memory contents to a guest (bsc#1124735).
- CVE-2017-18249: The add_free_nid function in fs/f2fs/node.c did not properly track an allocated nid, which allowed local users to cause a denial of service (race condition) or possibly have unspecified other impact via concurrent threads (bnc#1087036).

The following non-security bugs were fixed:

- acpi/nfit: Block function zero DSMs (bsc#1123321).
- acpi, nfit: Fix ARS overflow continuation (bsc#1125000).
- acpi/nfit: fix cmd_rc for acpi_nfit_ctl to always return a value (bsc#1124775).
- acpi/nfit: Fix command-supported detection (bsc#1123323).
- acpi: power: Skip duplicate power resource references in _PRx (bnc#1012382).
- acpi / processor: Fix the return value of acpi_processor_ids_walk() (git fixes (acpi)).
- alpha: Fix Eiger NR_IRQS to 128 (bnc#1012382).
- alpha: fix page fault handling for r16-r18 targets (bnc#1012382).
- alsa: bebob: fix model-id of unit for Apogee Ensemble (bnc#1012382).
- alsa: compress: Fix stop handling on compressed capture streams (bnc#1012382).
- alsa: hda - Add quirk for HP EliteBook 840 G5 (bnc#1012382).
- alsa: hda/realtek - Disable headset Mic VREF for headset mode of ALC225 (bnc#1012382).
- alsa: hda - Serialize codec registrations (bnc#1012382).
- alsa: usb-audio: Fix implicit fb endpoint setup by quirk (bnc#1012382).
- ARC: perf: map generic branches to correct hardware condition (bnc#1012382).
- arm64: Do not trap host pointer auth use to EL2 (bnc#1012382).
- arm64: ftrace: do not adjust the LR value (bnc#1012382).
- arm64: hyp-stub: Forbid kprobing of the hyp-stub (bnc#1012382).
- arm64/kvm: consistently handle host HCR_EL2 flags ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.4.176~4.25.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.4.176~4.25.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.4.176~4.25.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.4.176~4.25.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.4.176~4.25.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.4.176~4.25.1", rls:"SLES12.0SP3"))) {
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
