# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2374.1");
  script_cve_id("CVE-2017-18344", "CVE-2018-14734", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-16 18:47:23 +0000 (Fri, 16 Nov 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2374-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2374-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182374-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1023711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1076110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089343");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1090888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1091107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1093777");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1095643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1096978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1097771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1098599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1099993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101658");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1101789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102215");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/997935");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-August/004449.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2374-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP3 Azure kernel was updated to 4.4.143 to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-3620: Local attackers on baremetal systems could use speculative code patterns on hyperthreaded processors to read data present in the L1 Datacache used by other hyperthreads on
the same CPU core, potentially leaking sensitive data. (bnc#1087081).
- CVE-2018-3646: Local attackers in virtualized guest systems could use speculative code patterns on hyperthreaded processors to read data present in the L1 Datacache used by other hyperthreads on the same CPU core, potentially leaking sensitive data, even from other virtual machines or the host system. (bnc#1089343).
- CVE-2018-5391: A flaw in the IP packet reassembly could be used by remote attackers to consume CPU time (bnc#1103097).
- CVE-2018-5390: Linux kernel versions 4.9+ can be forced to make very expensive calls to tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() for every incoming packet which can lead to a denial of service (bnc#1102340).
- CVE-2018-14734: drivers/infiniband/core/ucma.c allowed ucma_leave_multicast to access a certain data structure after a cleanup step in ucma_process_join, which allowed attackers to cause a denial of service (use-after-free) (bnc#1103119).
- CVE-2017-18344: The timer_create syscall implementation in kernel/time/posix-timers.c didn't properly validate the sigevent->sigev_notify field, which leads to out-of-bounds access in the show_timer function (called when /proc/$PID/timers is read). This allowed userspace applications to read arbitrary kernel memory (on a kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE) (bnc#1102851 1103580).

The following non-security bugs were fixed:

- 1wire: family module autoload fails because of upper/lower case mismatch (bnc#1012382).
- Add support for 5,25,50, and 100G to 802.3ad bonding driver (bsc#1096978)
- ahci: Disable LPM on Lenovo 50 series laptops with a too old BIOS (bnc#1012382).
- alsa: hda - Fix pincfg at resume on Lenovo T470 dock (bsc#1099810).
- alsa: hda - Handle kzalloc() failure in snd_hda_attach_pcm_stream() (bnc#1012382).
- alsa: hda/realtek - set PINCFG_HEADSET_MIC to parse_flags (bsc#1099810).
- arm64: do not open code page table entry creation (bsc#1102197).
- arm64: kpti: Use early_param for kpti= command-line option (bsc#1102188).
- arm64: Make sure permission updates happen for pmd/pud (bsc#1102197).
- arm: 8764/1: kgdb: fix NUMREGBYTES so that gdb_regs[] is the correct size (bnc#1012382).
- arm: dts: imx6q: Use correct SDMA script for SPI5 core (bnc#1012382).
- ASoC: cirrus: i2s: Fix LRCLK configuration (bnc#1012382).
- ASoC: cirrus: i2s: Fix {TX<pipe>RX}LinCtrlData setup (bnc#1012382).
- ASoC: dapm: delete dapm_kcontrol_data paths list before freeing it (bnc#1012382).
- ath10k: fix rfc1042 header retrieval in QCA4019 with eth decap mode ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP Applications 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.4.143~4.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.4.143~4.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.4.143~4.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.4.143~4.13.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.4.143~4.13.1", rls:"SLES12.0SP3"))) {
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
