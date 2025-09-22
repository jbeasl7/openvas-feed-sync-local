# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1693.1");
  script_cve_id("CVE-2019-20810", "CVE-2020-10766", "CVE-2020-10767", "CVE-2020-10768", "CVE-2020-13974");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-15 18:42:18 +0000 (Mon, 15 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1693-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1693-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201693-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1148868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1162063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172781");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172884");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-June/006989.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:1693-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2020-10768: The prctl() function could be used to enable indirect branch speculation even after it has been disabled. (bnc#1172783)
- CVE-2020-10766: A bug in the logic handling could allow an attacker with a local account to disable SSBD protection. (bnc#1172781)
- CVE-2020-10767: A IBPB would be disabled when STIBP was not available or when Enhanced Indirect Branch Restricted Speculation (IBRS) was available. This is unexpected behaviour could leave the system open to a spectre v2 style attack (bnc#1172782)
- CVE-2020-13974: drivers/tty/vt/keyboard.c had an integer overflow if k_ascii was called several times in a row (bnc#1172775)
- CVE-2019-20810: go7007_snd_init did not call snd_card_free for a failure path, which caused a memory leak (bnc#1172458)

The following non-security bugs were fixed:

- ACPI: PM: Avoid using power resources if there are none for D0 (bsc#1051510).
- ALSA: es1688: Add the missed snd_card_free() (bsc#1051510).
- ALSA: hda/hdmi - enable runtime pm for newer AMD display audio (bsc#1111666).
- ALSA: hda/realtek - Add LED class support for micmute LED (bsc#1111666).
- ALSA: hda/realtek - Enable micmute LED on and HP system (bsc#1111666).
- ALSA: hda/realtek - Fix unused variable warning w/o CONFIG_LEDS_TRIGGER_AUDIO (bsc#1111666).
- ALSA: hda/realtek - Introduce polarity for micmute LED GPIO (bsc#1111666).
- ALSA: hda/realtek - add a pintbl quirk for several Lenovo machines (bsc#1111666).
- ALSA: hda: Add ElkhartLake HDMI codec vid (bsc#1111666).
- ALSA: hda: add sienna_cichlid audio asic id for sienna_cichlid up (bsc#1111666).
- ALSA: pcm: disallow linking stream to itself (bsc#1111666).
- ALSA: usb-audio: Add Pioneer DJ DJM-900NXS2 support (bsc#1111666).
- ALSA: usb-audio: Add duplex sound support for USB devices using implicit feedback (bsc#1111666).
- ALSA: usb-audio: Add vendor, product and profile name for HP Thunderbolt Dock (bsc#1111666).
- ALSA: usb-audio: Clean up quirk entries with macros (bsc#1111666).
- ALSA: usb-audio: Fix inconsistent card PM state after resume (bsc#1111666).
- ALSA: usb-audio: Fix racy list management in output queue (bsc#1111666).
- ALSA: usb-audio: Manage auto-pm of all bundled interfaces (bsc#1111666).
- ALSA: usb-audio: Use the new macro for HP Dock rename quirks (bsc#1111666).
- CDC-ACM: heed quirk also in error handling (git-fixes).
- HID: sony: Fix for broken buttons on DS3 USB dongles (bsc#1051510).
- KVM: x86/mmu: Set mmio_value to '0' if reserved #PF can't be generated (bsc#1171904).
- KVM: x86: only do L1TF workaround on affected processors (bsc#1171904).
- NFS: Fix an RCU lock leak in nfs4_refresh_delegation_stateid() (bsc#1170592).
- NFSv4: Retry CLOSE and DELEGRETURN on NFS4ERR_OLD_STATEID (bsc#1170592).
- PCI/PM: Call .bridge_d3() hook only if non-NULL ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.26.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.26.1", rls:"SLES12.0SP5"))) {
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
