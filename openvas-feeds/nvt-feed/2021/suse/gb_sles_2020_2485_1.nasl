# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2485.1");
  script_cve_id("CVE-2020-14314", "CVE-2020-14356", "CVE-2020-16166");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:55 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-25 19:17:14 +0000 (Tue, 25 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2485-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2485-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202485-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2485-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-14314: Fixed a potential negative array index in ext4
 (bsc#1173798).

CVE-2020-14356: Fixed a NULL pointer dereference in the cgroupv2
 subsystem (bsc#1175213).

CVE-2020-16166: Fixed an information leak in the network RNG
 (bnc#1174757).

The following non-security bugs were fixed:

9p/trans_fd: Fix concurrency del of req_list in
 p9_fd_cancelled/p9_read_work (git-fixes).

ACPICA: Do not increment operation_region reference counts for field
 units (git-fixes).

ALSA: atmel: Remove invalid 'fall through' comments (git-fixes).

ALSA: core: pcm_iec958: fix kernel-doc (git-fixes).

ALSA: echoaduio: Drop superfluous volatile modifier (git-fixes).

ALSA: echoaudio: Address bugs in the interrupt handling (git-fixes).

ALSA: echoaudio: Fix potential Oops in snd_echo_resume() (git-fixes).

ALSA: echoaudio: Prevent races in calls to set_audio_format()
 (git-fixes).

ALSA: echoaudio: Prevent some noise on unloading the module (git-fixes).

ALSA: echoaudio: Race conditions around 'opencount' (git-fixes).

ALSA: echoaudio: Remove redundant check (git-fixes).

ALSA: echoaudio: re-enable IRQs on failure path (git-fixes).

ALSA: firewire: fix kernel-doc (git-fixes).

ALSA: hda - fix the micmute led status for Lenovo ThinkCentre AIO
 (git-fixes).

ALSA: hda - reverse the setting value in the micmute_led_set (git-fixes).

ALSA: hda/ca0132 - Add new quirk ID for Recon3D (git-fixes).

ALSA: hda/ca0132 - Fix AE-5 microphone selection commands (git-fixes).

ALSA: hda/ca0132 - Fix ZxR Headphone gain control get value (git-fixes).

ALSA: hda/hdmi: Add quirk to force connectivity (git-fixes).

ALSA: hda/hdmi: Fix keep_power assignment for non-component devices
 (git-fixes).

ALSA: hda/hdmi: Use force connectivity quirk on another HP desktop
 (git-fixes).

ALSA: hda/realtek - Fix unused variable warning (git-fixes).

ALSA: hda/realtek - Fixed HP right speaker no sound (git-fixes).

ALSA: hda/realtek: Add alc269/alc662 pin-tables for Loongson-3 laptops
 (git-fixes).

ALSA: hda/realtek: Add model alc298-samsung-headphone (git-fixes).

ALSA: hda/realtek: Add quirk for Samsung Galaxy Book Ion (git-fixes).

ALSA: hda/realtek: Add quirk for Samsung Galaxy Flex Book (git-fixes).

ALSA: hda/realtek: Fix add a 'ultra_low_power' function for intel
 reference board (alc256) (git-fixes).

ALSA: hda/realtek: Fix pin default on Intel NUC 8 Rugged (git-fixes).

ALSA: hda/realtek: enable headset mic of ASUS ROG Zephyrus G15(GA502)
 series with ALC289 (git-fixes).

ALSA: hda/realtek: typo_fix: enable headset mic of ASUS ROG Zephyrus
 G14(GA401) series with ALC289 (git-fixes).

ALSA: hda/tegra: Disable sync-write operation (git-fixes).

ALSA: hda: Add support for Loongson 7A1000 controller (git-fixes).

ALSA: hda: Enable sync-write operation as default for all ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~18.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~18.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~18.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~18.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~18.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~18.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~18.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~18.15.1", rls:"SLES15.0SP2"))) {
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
