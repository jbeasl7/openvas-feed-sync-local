# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.0836.1");
  script_cve_id("CVE-2019-19768", "CVE-2020-8647", "CVE-2020-8648", "CVE-2020-8649", "CVE-2020-9383");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:06 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-18 20:09:12 +0000 (Wed, 18 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:0836-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:0836-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20200836-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:0836-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15-SP1 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-8647: Fixed a use-after-free in the vc_do_resize function in
 drivers/tty/vt/vt.c (bsc#1162929).

CVE-2020-8649: Fixed a use-after-free in the vgacon_invert_region
 function in drivers/video/console/vgacon.c (bsc#1162931).

CVE-2020-8648: Fixed a use-after-free in the n_tty_receive_buf_common
 function in drivers/tty/n_tty.c (bsc#1162928).

CVE-2020-9383: Fixed an out-of-bounds read due to improper error
 condition check of FDC index (bsc#1165111).

CVE-2019-19768: Fixed a use-after-free in the __blk_add_trace function
 in kernel/trace/blktrace.c (bnc#1159285).

The following non-security bugs were fixed:

ALSA: hda/realtek - Add Headset Button supported for ThinkPad X1
 (bsc#1111666).

ALSA: hda/realtek - Add Headset Mic supported (bsc#1111666).

ALSA: hda/realtek - Add more codec supported Headset Button
 (bsc#1111666).

ALSA: hda/realtek - Apply quirk for MSI GP63, too (bsc#1111666).

ALSA: hda/realtek - Apply quirk for yet another MSI laptop (bsc#1111666).

ALSA: hda/realtek - Enable the headset of ASUS B9450FA with ALC294
 (bsc#1111666).

ALSA: hda/realtek - Fix a regression for mute led on Lenovo Carbon X1
 (bsc#1111666).

ALSA: hda/realtek - Fix silent output on Gigabyte X570 Aorus Master
 (bsc#1111666).

ALSA: usb-audio: Add boot quirk for MOTU M Series (bsc#1111666).

ALSA: usb-audio: Add clock validity quirk for Denon MC7000/MCX8000
 (bsc#1111666).

ALSA: usb-audio: add implicit fb quirk for MOTU M Series (bsc#1111666).

ALSA: usb-audio: add quirks for Line6 Helix devices fw>=2.82
 (bsc#1111666).

ALSA: usb-audio: Apply 48kHz fixed rate playback for Jabra Evolve 65
 headset (bsc#1111666).

ALSA: usb-audio: fix Corsair Virtuoso mixer label collision
 (bsc#1111666).

ALSA: usb-audio: Fix UAC2/3 effect unit parsing (bsc#1111666).

ALSA: usb-audio: unlock on error in probe (bsc#1111666).

ALSA: usb-audio: Use lower hex numbers for IDs (bsc#1111666).

ALSA: usx2y: Adjust indentation in snd_usX2Y_hwdep_dsp_status
 (bsc#1051510).

amdgpu/gmc_v9: save/restore sdpif regs during S3 (bsc#1113956)

ASoC: dapm: Correct DAPM handling of active widgets during shutdown
 (bsc#1051510).

ASoC: pcm512x: Fix unbalanced regulator enable call in probe error path
 (bsc#1051510).

ASoC: pcm: Fix possible buffer overflow in dpcm state sysfs output
 (bsc#1051510).

ASoC: pcm: update FE/BE trigger order based on the command (bsc#1051510).

ASoC: topology: Fix memleak in soc_tplg_link_elems_load() (bsc#1051510).

atm: zatm: Fix empty body Clang warnings (bsc#1051510).

b43legacy: Fix -Wcast-function-type (bsc#1051510).

blk: Fix kabi due to blk_trace_mutex addition (bsc#1159285).

blktrace: fix dereference after null check (bsc#1159285).

blktrace: fix trace mutex deadlock (bsc#1159285).

bnxt_en: Fix NTUPLE firmware command failures (bsc#1104745 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~197.37.1", rls:"SLES15.0SP1"))) {
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
