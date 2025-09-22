# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3507.1");
  script_cve_id("CVE-2020-25668", "CVE-2020-25704", "CVE-2020-25705");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:48 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 12:33:42 +0000 (Fri, 04 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3507-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3507-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203507-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3507-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-25705: A flaw in the way reply ICMP packets are limited in was
 found that allowed to quickly scan open UDP ports. This flaw allowed an
 off-path remote user to effectively bypassing source port UDP
 randomization. The highest threat from this vulnerability is to
 confidentiality and possibly integrity, because software and services
 that rely on UDP source port randomization (like DNS) are indirectly
 affected as well. Kernel versions may be vulnerable to this issue
 (bsc#1175721, bsc#1178782).

CVE-2020-25704: Fixed a memory leak in perf_event_parse_addr_filter()
 (bsc#1178393).

CVE-2020-25668: Fixed a use-after-free in con_font_op() (bnc#1178123).

The following non-security bugs were fixed:

9P: Cast to loff_t before multiplying (git-fixes).

acpi-cpufreq: Honor _PSD table setting on new AMD CPUs (git-fixes).

ACPI: debug: do not allow debugging when ACPI is disabled (git-fixes).

ACPI: dock: fix enum-conversion warning (git-fixes).

ACPI / extlog: Check for RDMSR failure (git-fixes).

ACPI: NFIT: Fix comparison to '-ENXIO' (git-fixes).

ACPI: video: use ACPI backlight for HP 635 Notebook (git-fixes).

ALSA: hda - Fix the return value if cb func is already registered
 (git-fixes).

ALSA: hda: prevent undefined shift in snd_hdac_ext_bus_get_link()
 (git-fixes).

ata: sata_rcar: Fix DMA boundary mask (git-fixes).

ath10k: fix VHT NSS calculation when STBC is enabled (git-fixes).

ath10k: start recovery process when payload length exceeds max htc
 length for sdio (git-fixes).

bus/fsl_mc: Do not rely on caller to provide non NULL mc_io (git-fixes).

can: can_create_echo_skb(): fix echo skb generation: always use
 skb_clone() (git-fixes).

can: dev: __can_get_echo_skb(): fix real payload length return value for
 RTR frames (git-fixes).

can: dev: can_get_echo_skb(): prevent call to kfree_skb() in hard IRQ
 context (git-fixes).

can: peak_canfd: pucan_handle_can_rx(): fix echo management when
 loopback is on (git-fixes).

can: peak_usb: add range checking in decode operations (git-fixes).

can: peak_usb: peak_usb_get_ts_time(): fix timestamp wrapping
 (git-fixes).

can: rx-offload: do not call kfree_skb() from IRQ context (git-fixes).

clk: ti: clockdomain: fix static checker warning (git-fixes).

crypto: bcm - Verify GCM/CCM key length in setkey (git-fixes).

device property: Do not clear secondary pointer for shared primary
 firmware node (git-fixes).

device property: Keep secondary firmware node secondary by type
 (git-fixes).

drbd: code cleanup by using sendpage_ok() to check page for
 kernel_sendpage() (bsc#1172873).

drm/amd/display: Do not invoke kgdb_breakpoint() unconditionally
 (git-fixes).

drm/amd/display: HDMI remote sink need mode validation for Linux
 (git-fixes).

drm/amdgpu: do not map BO in reserved region ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~197.72.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~197.72.1", rls:"SLES15.0SP1"))) {
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
