# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833031");
  script_version("2025-02-26T05:38:40+0000");
  script_cve_id("CVE-2021-26341", "CVE-2021-4157", "CVE-2022-1012", "CVE-2022-1679", "CVE-2022-20132", "CVE-2022-20154", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-33981", "CVE-2022-34918");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-30 16:34:07 +0000 (Fri, 30 Sep 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:45:09 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2022:2424-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeapMicro5\.2");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2424-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NQBAQOEVMNDMJLZJ3VYM6W3VQVEMA7X7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2022:2424-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 RT kernel was updated to 3.12.31 to
     receive various security and bugfixes.
  The following security bugs were fixed:

  - CVE-2022-29900, CVE-2022-29901: Fixed the RETBLEED attack, a new Spectre
       like Branch Target Buffer attack, that can leak arbitrary kernel
       information (bsc#1199657).

  - CVE-2022-34918: Fixed a buffer overflow with nft_set_elem_init() that
       could be used by a local attacker to escalate privileges (bnc#1201171).

  - CVE-2021-26341: Some AMD CPUs may transiently execute beyond
       unconditional direct branches, which may potentially result in data
       leakage (bsc#1201050).

  - CVE-2022-1679: Fixed a use-after-free in the Atheros wireless driver in
       the way a user forces the ath9k_htc_wait_for_target function to fail
       with some input messages (bsc#1199487).

  - CVE-2022-20132: Fixed out of bounds read due to improper input
       validation in lg_probe and related functions of hid-lg.c (bsc#1200619).

  - CVE-2022-1012: Fixed information leak caused by small table perturb size
       in the TCP source port generation algorithm (bsc#1199482).

  - CVE-2022-33981: Fixed use-after-free in floppy driver (bsc#1200692)

  - CVE-2021-4157: Fixed an out of memory bounds write flaw in the NFS
       subsystem, related to the replication of files with NFS. A user could
       potentially crash the system or escalate privileges on the system
       (bsc#1194013).

  - CVE-2022-20154: Fixed a use after free due to a race condition in
       lock_sock_nested of sock.c. This could lead to local escalation of
       privilege with System execution privileges needed (bsc#1200599).
  The following non-security bugs were fixed:

  - Add missing recommends of kernel-install-tools to kernel-source-vanilla
       (bsc#1200442)

  - Add various fsctl structs (bsc#1200217).

  - ALSA: hda/conexant: Fix missing beep setup (git-fixes).

  - ALSA: hda/realtek - Add HW8326 support (git-fixes).

  - ALSA: hda/realtek: Add quirk for Clevo PD70PNT (git-fixes).

  - ALSA: hda/realtek - ALC897 headset MIC no sound (git-fixes).

  - ALSA: hda/via: Fix missing beep setup (git-fixes).

  - arm64: dts: rockchip: Move drive-impedance-ohm to emmc phy on rk3399
       (git-fixes)

  - arm64: ftrace: fix branch range checks (git-fixes)

  - ASoC: cs35l36: Update digital volume TLV (git-fixes).

  - ASoC: cs42l52: Correct TLV for Bypass Volume (git-fixes).

  - ASoC: cs42l52: Fix TLV scales for mixer controls (git-fixes).

  - ASoC: cs42l56: Correct typo in minimum level for ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap Micro 5.2.");

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

if(release == "openSUSELeapMicro5.2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.3.18~150300.96.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.3.18~150300.96.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.3.18~150300.96.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.3.18~150300.96.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.3.18~150300.96.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.3.18~150300.96.1", rls:"openSUSELeapMicro5.2"))) {
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