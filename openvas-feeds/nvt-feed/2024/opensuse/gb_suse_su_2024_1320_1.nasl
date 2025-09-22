# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856084");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-46925", "CVE-2021-46926", "CVE-2021-46927", "CVE-2021-46929", "CVE-2021-46930", "CVE-2021-46931", "CVE-2021-46933", "CVE-2021-46936", "CVE-2021-47082", "CVE-2021-47087", "CVE-2021-47091", "CVE-2021-47093", "CVE-2021-47094", "CVE-2021-47095", "CVE-2021-47096", "CVE-2021-47097", "CVE-2021-47098", "CVE-2021-47099", "CVE-2021-47100", "CVE-2021-47101", "CVE-2021-47102", "CVE-2021-47104", "CVE-2021-47105", "CVE-2021-47107", "CVE-2021-47108", "CVE-2022-48626", "CVE-2022-48629", "CVE-2022-48630", "CVE-2023-35827", "CVE-2023-52450", "CVE-2023-52454", "CVE-2023-52469", "CVE-2023-52470", "CVE-2023-52474", "CVE-2023-52477", "CVE-2023-52492", "CVE-2023-52497", "CVE-2023-52501", "CVE-2023-52502", "CVE-2023-52504", "CVE-2023-52507", "CVE-2023-52508", "CVE-2023-52509", "CVE-2023-52510", "CVE-2023-52511", "CVE-2023-52513", "CVE-2023-52515", "CVE-2023-52517", "CVE-2023-52519", "CVE-2023-52520", "CVE-2023-52523", "CVE-2023-52524", "CVE-2023-52525", "CVE-2023-52528", "CVE-2023-52529", "CVE-2023-52532", "CVE-2023-52564", "CVE-2023-52566", "CVE-2023-52567", "CVE-2023-52569", "CVE-2023-52574", "CVE-2023-52575", "CVE-2023-52576", "CVE-2023-52582", "CVE-2023-52583", "CVE-2023-52597", "CVE-2023-52605", "CVE-2023-52621", "CVE-2024-25742", "CVE-2024-26600");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-17 17:15:54 +0000 (Wed, 17 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-04-19 01:03:25 +0000 (Fri, 19 Apr 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:1320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1320-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RRD6KAYR75P3MHZXRLZ7MIU2KHUW5VDA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:1320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 RT kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2021-46925: Fixed kernel panic caused by race of smc_sock (bsc#1220466).

  * CVE-2021-46926: Fixed bug when detecting controllers in ALSA/hda/intel-sdw-
      acpi (bsc#1220478).

  * CVE-2021-46927: Fixed assertion bug in nitro_enclaves: Use
      get_user_pages_unlocked() (bsc#1220443).

  * CVE-2021-46929: Fixed use-after-free issue in sctp_sock_dump()
      (bsc#1220482).

  * CVE-2021-46930: Fixed usb/mtu3 list_head check warning (bsc#1220484).

  * CVE-2021-46931: Fixed wrong type casting in mlx5e_tx_reporter_dump_sq()
      (bsc#1220486).

  * CVE-2021-46933: Fixed possible underflow in ffs_data_clear() (bsc#1220487).

  * CVE-2021-46936: Fixed use-after-free in tw_timer_handler() (bsc#1220439).

  * CVE-2021-47082: Fixed ouble free in tun_free_netdev() (bsc#1220969).

  * CVE-2021-47087: Fixed incorrect page free bug in tee/optee (bsc#1220954).

  * CVE-2021-47091: Fixed locking in ieee80211_start_ap()) error path
      (bsc#1220959).

  * CVE-2021-47093: Fixed memleak on registration failure in intel_pmc_core
      (bsc#1220978).

  * CVE-2021-47094: Fixed possible memory leak in KVM x86/mmu (bsc#1221551).

  * CVE-2021-47095: Fixed missing initialization in ipmi/ssif (bsc#1220979).

  * CVE-2021-47096: Fixed uninitialized user_pversion in ALSA rawmidi
      (bsc#1220981).

  * CVE-2021-47097: Fixed stack out of bound access in
      elantech_change_report_id() (bsc#1220982).

  * CVE-2021-47098: Fixed integer overflow/underflow in hysteresis calculations
      hwmon: (lm90) (bsc#1220983).

  * CVE-2021-47099: Fixed BUG_ON assertion in veth when skb entering GRO are
      cloned (bsc#1220955).

  * CVE-2021-47100: Fixed UAF when uninstall in ipmi (bsc#1220985).

  * CVE-2021-47101: Fixed uninit-value in asix_mdio_read() (bsc#1220987).

  * CVE-2021-47102: Fixed incorrect structure access In line: upper =
      info->upper_dev in net/marvell/prestera (bsc#1221009).

  * CVE-2021-47104: Fixed memory leak in qib_user_sdma_queue_pkts()
      (bsc#1220960).

  * CVE-2021-47105: Fixed potential memory leak in ice/xsk (bsc#1220961).

  * CVE-2021-47107: Fixed READDIR buffer overflow in NFSD (bsc#1220965).

  * CVE-2021-47108: Fixed possible NULL pointer dereference for mtk_hdmi_conf in
      drm/mediatek (bsc#1220986).

  * CVE-2022-48626: Fixed a potential use-after-free on remove path moxart
      (bsc#1220366).

  * CVE-2022-48629: Fixed possible memory leak in qcom-r ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150400.15.76.1", rls:"openSUSELeapMicro5.4"))) {
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
