# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0098.1");
  script_cve_id("CVE-2018-20669", "CVE-2019-20934", "CVE-2020-0444", "CVE-2020-0465", "CVE-2020-0466", "CVE-2020-15436", "CVE-2020-27068", "CVE-2020-27777", "CVE-2020-27786", "CVE-2020-27825", "CVE-2020-29371", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-4788");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-09 02:12:54 +0000 (Thu, 09 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0098-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0098-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210098-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1040855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1044767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1050545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056653");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056787");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1064802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1094840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104389");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1110096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1115431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1122971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152457");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1164780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174852");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178270");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178590");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179406");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179421");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179578");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179671");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179714");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179715");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180506");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-January/008184.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0098-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

- CVE-2018-20669: Fixed an improper check i915_gem_execbuffer2_ioctl in drivers/gpu/drm/i915/i915_gem_execbuffer.c (bsc#1122971).
- CVE-2019-20934: Fixed a use-after-free in show_numa_stats() because NUMA fault statistics were inappropriately freed, aka CID-16d51a590a8c (bsc#1179663).
- CVE-2020-0444: Fixed a bad kfree due to a logic error in audit_data_to_entry (bnc#1180027).
- CVE-2020-0465: Fixed multiple missing bounds checks in hid-multitouch.c that could have led to local privilege escalation (bnc#1180029).
- CVE-2020-0466: Fixed a use-after-free due to a logic error in do_epoll_ctl and ep_loop_check_proc of eventpoll.c (bnc#1180031).
- CVE-2020-4788: Fixed an issue with IBM Power9 processors could have allowed a local user to obtain sensitive information from the data in the L1 cache under extenuating circumstances (bsc#1177666).
- CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c which could have allowed local users to gain privileges or cause a denial of service (bsc#1179141).
- CVE-2020-27068: Fixed an out-of-bounds read due to a missing bounds check in the nl80211_policy policy of nl80211.c (bnc#1180086).
- CVE-2020-27777: Fixed a privilege escalation in the Run-Time Abstraction Services (RTAS) interface, affecting guests running on top of PowerVM or KVM hypervisors (bnc#1179107).
- CVE-2020-27786: Fixed an out-of-bounds write in the MIDI implementation (bnc#1179601).
- CVE-2020-27825: Fixed a race in the trace_open and buffer resize calls (bsc#1179960).
- CVE-2020-29371: Fixed uninitialized memory leaks to userspace (bsc#1179429).
- CVE-2020-29660: Fixed a locking inconsistency in the tty subsystem that may have allowed a read-after-free attack against TIOCGSID (bnc#1179745).
- CVE-2020-29661: Fixed a locking issue in the tty subsystem that allowed a use-after-free attack against TIOCSPGRP (bsc#1179745).

The following non-security bugs were fixed:

- ALSA: hda/ca0132 - Change Input Source enum strings (git-fixes).
- ALSA: hda/ca0132 - Fix AE-5 rear headphone pincfg (git-fixes).
- ALSA: hda/realtek - Add new codec supported for ALC897 (git-fixes).
- ALSA: hda/realtek: Add mute LED quirk to yet another HP x360 model (git-fixes).
- ALSA: hda/realtek: Add some Clove SSID in the ALC293(ALC1220) (git-fixes).
- ALSA: hda/realtek: Enable headset of ASUS UX482EG & B9400CEA with ALC294 (git-fixes).
- ALSA: hda: Fix regressions on clear and reconfig sysfs (git-fixes).
- ALSA: usb-audio: US16x08: fix value count for level meters (git-fixes).
- ASoC: arizona: Fix a wrong free in wm8997_probe (git-fixes).
- ASoC: cx2072x: Fix doubly definitions of Playback and Capture streams (git-fixes).
- ASoC: jz4740-i2s: add missed checks for clk_get() (git-fixes).
- ASoC: pcm: DRAIN support reactivation (git-fixes).
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.41.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.41.1", rls:"SLES12.0SP5"))) {
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
