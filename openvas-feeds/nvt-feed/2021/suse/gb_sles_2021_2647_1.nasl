# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2647.1");
  script_cve_id("CVE-2020-0429", "CVE-2020-36386", "CVE-2021-22543", "CVE-2021-3659", "CVE-2021-37576");
  script_tag(name:"creation_date", value:"2021-08-11 02:25:15 +0000 (Wed, 11 Aug 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-05 18:09:19 +0000 (Thu, 05 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2647-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2647-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212647-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188973");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-August/009280.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2647-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2021-3659: Fixed a NULL pointer dereference in llsec_key_alloc() in net/mac802154/llsec.c (bsc#1188876).
- CVE-2021-22543: Fixed improper handling of VM_IO<pipe>VM_PFNMAP vmas in KVM, which could bypass RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allowed users with the ability to start and control a VM to read/write random pages of memory and can result in local privilege escalation (bsc#1186482).
- CVE-2021-37576: Fixed an issue on the powerpc platform, where a KVM guest OS user could cause host OS memory corruption via rtas_args.nargs (bsc#1188838).
- CVE-2020-0429: In l2tp_session_delete and related functions of l2tp_core.c, there is possible memory corruption due to a use after free. This could lead to local escalation of privilege with System execution privileges needed. (bsc#1176724).
- CVE-2020-36386: Fixed a slab out-of-bounds read in hci_extended_inquiry_result_evt (bsc#1187038 ).

The following non-security bugs were fixed:

- ACPI: AMBA: Fix resource name in /proc/iomem (git-fixes).
- ACPI: bus: Call kobject_put() in acpi_init() error path (git-fixes).
- ACPI: processor idle: Fix up C-state latency if not ordered (git-fixes).
- ALSA: bebob: add support for ToneWeal FW66 (git-fixes).
- ALSA: hda: Add IRQ check for platform_get_irq() (git-fixes).
- ALSA: ppc: fix error return code in snd_pmac_probe() (git-fixes).
- ALSA: sb: Fix potential ABBA deadlock in CSP driver (git-fixes).
- ALSA: sb: Fix potential double-free of CSP mixer elements (git-fixes).
- ALSA: usb-audio: fix rate on Ozone Z90 USB headset (git-fixes).
- ASoC: soc-core: Fix the error return code in snd_soc_of_parse_audio_routing() (git-fixes).
- ASoC: tegra: Set driver_name=tegra for all machine drivers (git-fixes).
- Bluetooth: Fix the HCI to MGMT status conversion table (git-fixes).
- Bluetooth: Shutdown controller after workqueues are flushed or cancelled (git-fixes).
- Bluetooth: btusb: fix bt fiwmare downloading failure issue for qca btsoc (git-fixes).
- HID: wacom: Correct base usage for capacitive ExpressKey status bits (git-fixes).
- PCI/sysfs: Fix dsm_label_utf16s_to_utf8s() buffer overrun (git-fixes).
- PCI: Add ACS quirk for Broadcom BCM57414 NIC (git-fixes).
- PCI: Leave Apple Thunderbolt controllers on for s2idle or standby (git-fixes).
- PCI: quirks: fix false kABI positive (git-fixes).
- USB: cdc-acm: blacklist Heimann USB Appset device (git-fixes).
- USB: move many drivers to use DEVICE_ATTR_WO (git-fixes).
- USB: serial: cp210x: add ID for CEL EM3588 USB ZigBee stick (git-fixes).
- USB: serial: cp210x: fix comments for GE CS1000 (git-fixes).
- USB: serial: cp210x: fix comments for GE CS1000 (git-fixes).
- USB: serial: option: add support for u-blox LARA-R6 family (git-fixes).
- USB: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.83.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.83.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.83.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.83.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.83.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.83.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.83.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.83.1", rls:"SLES12.0SP5"))) {
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
