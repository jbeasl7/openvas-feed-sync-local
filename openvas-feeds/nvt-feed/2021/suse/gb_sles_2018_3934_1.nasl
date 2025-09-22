# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.3934.1");
  script_cve_id("CVE-2017-16533", "CVE-2017-18224", "CVE-2018-10940", "CVE-2018-16658", "CVE-2018-18386", "CVE-2018-18445", "CVE-2018-18710");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 14:29:55 +0000 (Thu, 06 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:3934-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:3934-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20183934-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1079524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103925");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104124");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111819");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112173");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112733");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112741");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113295");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1113972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114279");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-November/004903.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:3934-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel for Azure was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-18710: An information leak in cdrom_ioctl_select_disc in drivers/cdrom/cdrom.c could be used by local attackers to read kernel memory because a cast from unsigned long to int interferes with bounds checking. This is similar to CVE-2018-10940 and CVE-2018-16658 (bnc#1113751).
- CVE-2018-18445: Faulty computation of numeric bounds in the BPF verifier permits out-of-bounds memory accesses because adjust_scalar_min_max_vals in kernel/bpf/verifier.c mishandled 32-bit right shifts (bnc#1112372).
- CVE-2018-18386: drivers/tty/n_tty.c allowed local attackers (who are able to access pseudo terminals) to hang/block further usage of any pseudo terminal devices due to an EXTPROC versus ICANON confusion in TIOCINQ (bnc#1094825).
- CVE-2017-18224: fs/ocfs2/aops.c omits use of a semaphore and consequently has a race condition for access to the extent tree during read operations in DIRECT mode, which allowed local users to cause a denial of service (BUG) by modifying a certain e_cpos field (bnc#1084831).
- CVE-2017-16533: The usbhid_parse function in drivers/hid/usbhid/hid-core.c allowed local users to cause a denial of service (out-of-bounds read and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1066674).

The following non-security bugs were fixed:

- acpi, nfit: Prefer _DSM over _LSR for namespace label reads (bsc#112128).
- acpi / processor: Fix the return value of acpi_processor_ids_walk() (bsc#1051510).
- aio: fix io_destroy(2) vs. lookup_ioctx() race (git-fixes).
- alsa: hda: Add 2 more models to the power_save blacklist (bsc#1051510).
- alsa: hda - Add mic quirk for the Lenovo G50-30 (17aa:3905) (bsc#1051510).
- alsa: hda - Add quirk for ASUS G751 laptop (bsc#1051510).
- alsa: hda - Fix headphone pin config for ASUS G751 (bsc#1051510).
- alsa: hda: fix unused variable warning (bsc#1051510).
- alsa: hda/realtek - Cannot adjust speaker's volume on Dell XPS 27 7760 (bsc#1051510).
- alsa: hda/realtek - Fix the problem of the front MIC on the Lenovo M715 (bsc#1051510).
- alsa: usb-audio: update quirk for B&W PX to remove microphone (bsc#1051510).
- apparmor: Check buffer bounds when mapping permissions mask (git-fixes).
- ARM: bcm2835: Add GET_THROTTLED firmware property (bsc#1108468).
- ASoC: intel: skylake: Add missing break in skl_tplg_get_token() (bsc#1051510).
- ASoC: Intel: Skylake: Reset the controller in probe (bsc#1051510).
- ASoC: rsnd: adg: care clock-frequency size (bsc#1051510).
- ASoC: rsnd: do not fallback to PIO mode when -EPROBE_DEFER (bsc#1051510).
- ASoC: rt5514: Fix the issue of the delay volume applied again (bsc#1051510).
- ASoC: sigmadsp: safeload should not have lower byte limit (bsc#1051510).
- ASoC: wm8804: Add ACPI support (bsc#1051510).
- ath10k: fix kernel panic ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~6.3.1", rls:"SLES12.0SP4"))) {
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
