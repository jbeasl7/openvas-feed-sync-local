# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2223.1");
  script_cve_id("CVE-2017-18344", "CVE-2018-5390");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-11 13:07:17 +0000 (Thu, 11 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2223-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2223-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182223-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2223-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:
CVE-2018-5390 aka SegmentSmack: A remote attacker even with relatively low bandwidth could have caused lots of CPU usage by triggering the worst case scenario during IP and/or TCP fragment reassembly (bsc#1102340)
CVE-2017-18344: The timer_create syscall implementation didn't properly validate input, which could have lead to out-of-bounds access. This allowed userspace applications to read arbitrary kernel memory in some setups. (bsc#1102851)
The following non-security bugs were fixed:
- acpi, apei, einj: Subtract any matching Register Region from Trigger
 resources (bsc#1051510).
- acpi, nfit: Fix scrub idle detection (bsc#1094119).
- acpi/nfit: fix cmd_rc for acpi_nfit_ctl to always return a value
 (bsc#1051510).
- acpi/processor: Finish making acpi_processor_ppc_has_changed() void
 (bsc#1051510).
- ahci: Disable Lpm on Lenovo 50 series laptops with a too old BIOS
 (bsc#1051510).
- alsa: hda - Handle pm failure during hotplug (bsc#1051510).
- alsa: hda/realtek - Add Panasonic CF-SZ6 headset jack quirk
 (bsc#1051510).
- alsa: hda/realtek - Yet another Clevo P950 quirk entry (bsc#1101143).
- alsa: hda/realtek - two more lenovo models need fixup of MIC_LOCATION
 (bsc#1051510).
- alsa: hda: add mute led support for HP ProBook 455 G5 (bsc#1051510).
- alsa: rawmidi: Change resized buffers atomically (bsc#1051510).
- alx: take rtnl before calling __alx_open from resume (bsc#1051510).
- arm64: kpti: Use early_param for kpti= command-line option (bsc#1103220).
- arm: module: fix modsign build error (bsc#1093666).
- asoc: mediatek: preallocate pages use platform device (bsc#1051510).
- ath9k_htc: Add a sanity check in ath9k_htc_ampdu_action() (bsc#1051510).
- atl1c: reserve min skb headroom (bsc#1051510).
- audit: Fix wrong task in comparison of session ID (bsc#1051510).
- audit: ensure that 'audit=1' actually enables audit for PID 1
 (bsc#1051510).
- audit: return on memory error to avoid null pointer dereference
 (bsc#1051510).
- b44: Initialize 64-bit stats seqcount (bsc#1051510).
- backlight: as3711_bl: Fix Device Tree node leaks (bsc#1051510).
- backlight: lm3630a: Bump REG_MAX value to 0x50 instead of 0x1F
 (bsc#1051510).
- batman-adv: Accept only filled wifi station info (bsc#1051510).
- batman-adv: Always initialize fragment header priority (bsc#1051510).
- batman-adv: Avoid race in TT TVLV allocator helper (bsc#1051510).
- batman-adv: Avoid storing non-TT-sync flags on singular entries too
 (bsc#1051510).
- batman-adv: Fix TT sync flags for intermediate TT responses
 (bsc#1051510).
- batman-adv: Fix bat_ogm_iv best gw refcnt after netlink dump
 (bsc#1051510).
- batman-adv: Fix bat_v best gw refcnt after netlink dump (bsc#1051510).
- batman-adv: Fix check of retrieved orig_gw in batadv_v_gw_is_eligible
 (bsc#1051510).
- batman-adv: Fix debugfs ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15, SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for Legacy Software 15, SUSE Linux Enterprise Module for Live Patching 15, SUSE Linux Enterprise Workstation Extension 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~25.6.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~25.6.1", rls:"SLES15.0"))) {
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
