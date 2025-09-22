# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2539.1");
  script_cve_id("CVE-2018-10853", "CVE-2018-10902", "CVE-2018-15572", "CVE-2018-9363");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-12 22:07:35 +0000 (Wed, 12 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2539-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2539-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182539-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2539-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2018-15572: The spectre_v2_select_mitigation function in
 arch/x86/kernel/cpu/bugs.c did not always fill RSB upon a context
 switch, which made it easier for attackers to conduct
 userspace-userspace spectreRSB attacks (bnc#1102517 bnc#1105296).
- CVE-2018-10902: It was found that the raw midi kernel driver did not
 protect against concurrent access which leads to a double realloc
 (double free) in snd_rawmidi_input_params() and
 snd_rawmidi_output_status() which are part of snd_rawmidi_ioctl()
 handler in rawmidi.c file. A malicious local attacker could possibly use
 this for privilege escalation (bnc#1105322).
- CVE-2018-9363: A buffer overflow in bluetooth HID report processing
 could be used by malicious bluetooth devices to crash the kernel or
 potentially execute code (bnc#1105292).
- CVE-2018-10853: A KVM guest userspace to guest kernel write was fixed,
 which could be used by guest users to crash the guest kernel
 (bnc#1097104).
The following non-security bugs were fixed:
- acpi / apei: Remove ghes_ioremap_area (bsc#1051510).
- acpi / pci: Bail early in acpi_pci_add_bus() if there is no ACPI handle
 (bsc#1051510).
- acpi / pm: save NVS memory for ASUS 1025C laptop (bsc#1051510).
- affs_lookup(): close a race with affs_remove_link() (bsc#1105355).
- alsa: cs5535audio: Fix invalid endian conversion (bsc#1051510).
- alsa: hda: Correct Asrock B85M-ITX power_save blacklist entry
 (bsc#1051510).
- alsa: hda - Sleep for 10ms after entering D3 on Conexant codecs
 (bsc#1051510).
- alsa: hda - Turn CX8200 into D3 as well upon reboot (bsc#1051510).
- alsa: memalloc: Do not exceed over the requested size (bsc#1051510).
- alsa: snd-aoa: add of_node_put() in error path (bsc#1051510).
- alsa: virmidi: Fix too long output trigger loop (bsc#1051510).
- alsa: vx222: Fix invalid endian conversions (bsc#1051510).
- alsa: vxpocket: Fix invalid endian conversions (bsc#1051510).
- arm64: enable thunderx gpio driver
- arm/asm/tlb.h: Fix build error implicit func declaration (bnc#1105467
 Reduce IPIs and atomic ops with improved lazy TLB).
- asoc: dpcm: do not merge format from invalid codec dai (bsc#1051510).
- asoc: es7134: remove 64kHz rate from the supported rates (bsc#1051510).
- asoc: Intel: cht_bsw_max98090: remove useless code, align with ChromeOS
 driver (bsc#1051510).
- asoc: Intel: cht_bsw_max98090_ti: Fix jack initialization (bsc#1051510).
- asoc: msm8916-wcd-digital: fix RX2 MIX1 and RX3 MIX1 (bsc#1051510).
- asoc: rsnd: cmd: Add missing newline to debug message (bsc#1051510).
- asoc: sirf: Fix potential NULL pointer dereference (bsc#1051510).
- asoc: zte: Fix incorrect PCM format bit usages (bsc#1051510).
- ata: Fix ZBC_OUT all bit handling (bsc#1051510).
- ata: Fix ZBC_OUT command block check (bsc#1051510).
- ath10k: prevent active scans ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15, SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for Legacy Software 15, SUSE Linux Enterprise Workstation Extension 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules", rpm:"lttng-modules~2.10.0~5.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules-debugsource", rpm:"lttng-modules-debugsource~2.10.0~5.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules-kmp-default", rpm:"lttng-modules-kmp-default~2.10.0_k4.12.14_25.16~5.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lttng-modules-kmp-default-debuginfo", rpm:"lttng-modules-kmp-default-debuginfo~2.10.0_k4.12.14_25.16~5.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~25.16.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~25.16.1", rls:"SLES15.0"))) {
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
