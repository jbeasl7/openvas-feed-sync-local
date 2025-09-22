# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2574.1");
  script_cve_id("CVE-2020-14314", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-14386", "CVE-2020-16166", "CVE-2020-1749", "CVE-2020-24394");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-22 18:24:17 +0000 (Tue, 22 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2574-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2574-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202574-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1074701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085308");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1120163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1166965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172871");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174387");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174844");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175063");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175064");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175396");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175407");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175409");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175423");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175440");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/show_bug.cgi?id=1166965#c16");
  script_xref(name:"URL", value:"https://build.opensuse.org/request/show/792664");
  script_xref(name:"URL", value:"https://github.com/sphinx-doc/sphinx/issues/7421");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-September/007381.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2574-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2020-1749: Use ip6_dst_lookup_flow instead of ip6_dst_lookup (bsc#1165629).
- CVE-2020-14314: Fixed a potential negative array index in do_split() (bsc#1173798).
- CVE-2020-14356: Fixed a null pointer dereference in cgroupv2 subsystem which could have led to privilege escalation (bsc#1175213).
- CVE-2020-14331: Fixed a missing check in vgacon scrollback handling (bsc#1174205).
- CVE-2020-16166: Fixed a potential issue which could have allowed remote attackers to make observations that help to obtain sensitive information about the internal state of the network RNG (bsc#1174757).
- CVE-2020-24394: Fixed an issue which could set incorrect permissions on new filesystem objects when the filesystem lacks ACL support (bsc#1175518).
- CVE-2020-14386: Fixed a potential local privilege escalation via memory corruption (bsc#1176069).

The following non-security bugs were fixed:

- ACPI: kABI fixes for subsys exports (bsc#1174968).
- ACPI / LPSS: Resume BYT/CHT I2C controllers from resume_noirq (bsc#1174968).
- ACPI / LPSS: Use acpi_lpss_* instead of acpi_subsys_* functions for hibernate (bsc#1174968).
- ACPI: PM: Introduce 'poweroff' callbacks for ACPI PM domain and LPSS (bsc#1174968).
- ACPI: PM: Simplify and fix PM domain hibernation callbacks (bsc#1174968).
- ALSA: core: pcm_iec958: fix kernel-doc (bsc#1111666).
- ALSA: echoaduio: Drop superfluous volatile modifier (bsc#1111666).
- ALSA: echoaudio: Fix potential Oops in snd_echo_resume() (bsc#1111666).
- ALSA: hda: Add support for Loongson 7A1000 controller (bsc#1111666).
- ALSA: hda/ca0132 - Add new quirk ID for Recon3D (bsc#1111666).
- ALSA: hda/ca0132 - Fix AE-5 microphone selection commands (bsc#1111666).
- ALSA: hda/ca0132 - Fix ZxR Headphone gain control get value (bsc#1111666).
- ALSA: hda: fix NULL pointer dereference during suspend (git-fixes).
- ALSA: hda: fix snd_hda_codec_cleanup() documentation (bsc#1111666).
- ALSA: hda - fix the micmute led status for Lenovo ThinkCentre AIO (bsc#1111666).
- ALSA: hda/realtek: Add alc269/alc662 pin-tables for Loongson-3 laptops (bsc#1111666).
- ALSA: hda/realtek: Add model alc298-samsung-headphone (git-fixes).
- ALSA: hda/realtek: Add mute LED and micmute LED support for HP systems (bsc#1111666).
- ALSA: hda/realtek - Add quirk for Lenovo Carbon X1 8th gen (bsc#1111666).
- ALSA: hda/realtek - Add quirk for MSI GE63 laptop (bsc#1111666).
- ALSA: hda/realtek - Add quirk for MSI GL63 (bsc#1111666).
- ALSA: hda/realtek: Add quirk for Samsung Galaxy Book Ion (git-fixes).
- ALSA: hda/realtek: Add quirk for Samsung Galaxy Flex Book (git-fixes).
- ALSA: hda/realtek - change to suitable link model for ASUS platform (bsc#1111666).
- ALSA: hda/realtek - Check headset type by unplug and resume (bsc#1111666).
- ALSA: hda/realtek - Enable audio jacks of ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.37.1", rls:"SLES12.0SP5"))) {
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
