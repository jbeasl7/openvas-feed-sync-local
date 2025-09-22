# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2416.1");
  script_cve_id("CVE-2020-36385", "CVE-2021-22555", "CVE-2021-33909", "CVE-2021-3609", "CVE-2021-3612");
  script_tag(name:"creation_date", value:"2021-07-21 06:49:19 +0000 (Wed, 21 Jul 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-13 18:30:21 +0000 (Tue, 13 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2416-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2416-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212416-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1153720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1187934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188273");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188274");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-July/009169.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:2416-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2021-22555: Fixed an heap out-of-bounds write in net/netfilter/x_tables.c that could allow local provilege escalation. (bsc#1188116)
- CVE-2021-33909: Fixed an out-of-bounds write in the filesystem layer that allows to obtain full root privileges. (bsc#1188062)
- CVE-2021-3609: Fixed a race condition in the CAN BCM networking protocol which allows for local privilege escalation. (bsc#1187215)
- CVE-2021-3612: Fixed an out-of-bounds memory write flaw which could allows a local user to crash the system or possibly escalate their privileges on the system. (bsc#1187585)
- CVE-2020-36385: Fixed a use-after-free flaw in ucma.c which allows for local privilege escalation. (bsc#1187050)

The following non-security bugs were fixed:

- ACPI: property: Constify stubs for CONFIG_ACPI=n case (git-fixes).
- ACPI: sysfs: Fix a buffer overrun problem with description_show() (git-fixes).
- ALSA: isa: Fix error return code in snd_cmi8330_probe() (git-fixes).
- arm_pmu: Fix write counter incorrect in ARMv7 big-endian mode (git-fixes).
- arm64/mm: Fix ttbr0 values stored in struct thread_info for software-pan (git-fixes).
- ASoC: cs42l42: Correct definition of CS42L42_ADC_PDN_MASK (git-fixes).
- ASoC: hisilicon: fix missing clk_disable_unprepare() on error in hi6210_i2s_startup() (git-fixes).
- ata: ahci_sunxi: Disable DIPM (git-fixes).
- ath10k: Fix an error code in ath10k_add_interface() (git-fixes).
- Bluetooth: mgmt: Fix slab-out-of-bounds in tlv_data_is_valid (git-fixes).
- brcmfmac: correctly report average RSSI in station info (git-fixes).
- brcmfmac: fix setting of station info chains bitmask (git-fixes).
- brcmsmac: mac80211_if: Fix a resource leak in an error handling path (git-fixes).
- can: gw: synchronize rcu operations before removing gw job entry (git-fixes).
- can: hi311x: hi3110_can_probe(): silence clang warning (git-fixes).
- can: peak_pciefd: pucan_handle_status(): fix a potential starvation issue in TX path (git-fixes).
- cfg80211: call cfg80211_leave_ocb when switching away from OCB (git-fixes).
- char: pcmcia: error out if 'num_bytes_read' is greater than 4 in set_protocol() (git-fixes).
- crypto: cavium/nitrox - Fix an error rhandling path in 'nitrox_probe()' (git-fixes).
- cxgb4: fix wrong shift (git-fixes).
- drm: qxl: ensure surf.data is ininitialized (git-fixes).
- drm/nouveau: wait for moving fence after pinning v2 (git-fixes).
- drm/radeon: wait for moving fence after pinning (git-fixes).
- drm/rockchip: cdn-dp-core: add missing clk_disable_unprepare() on error in cdn_dp_grf_write() (git-fixes).
- extcon: max8997: Add missing modalias string (git-fixes).
- extcon: sm5502: Drop invalid register write in sm5502_reg_data (git-fixes).
- fpga: stratix10-soc: Add missing fpga_mgr_free() call (git-fixes).
- fuse: check connected ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.80.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.80.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.80.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.80.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.80.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.80.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.80.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.80.1", rls:"SLES12.0SP5"))) {
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
