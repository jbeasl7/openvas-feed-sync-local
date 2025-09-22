# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3281.1");
  script_cve_id("CVE-2020-0430", "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-14351", "CVE-2020-16120", "CVE-2020-25212", "CVE-2020-25285", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25705", "CVE-2020-27673", "CVE-2020-27675");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-07 19:52:29 +0000 (Mon, 07 Dec 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3281-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3281-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203281-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1061843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1066382");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1077428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1114648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1152624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171675");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176560");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177101");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177271");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177685");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177687");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177724");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1177861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178187");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178188");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936888");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007756.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3281-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel Azure was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2020-25656: Fixed a concurrency use-after-free in vt_do_kdgkb_ioctl (bnc#1177766).
- CVE-2020-25285: Fixed a race condition between hugetlb sysctl handlers in mm/hugetlb.c (bnc#1176485).
- CVE-2020-0430: Fixed an OOB read in skb_headlen of /include/linux/skbuff.h (bnc#1176723).
- CVE-2020-14351: Fixed a race in the perf_mmap_close() function (bsc#1177086).
- CVE-2020-16120: Fixed a permissions issue in ovl_path_open() (bsc#1177470).
- CVE-2020-12351: Implemented a kABI workaround for bluetooth l2cap_ops filter addition (bsc#1177724).
- CVE-2020-12352: Fixed an information leak when processing certain AMP packets aka 'BleedingTooth' (bsc#1177725).
- CVE-2020-25212: Fixed a TOCTOU mismatch in the NFS client code (bnc#1176381).
- CVE-2020-25645: Fixed an issue in IPsec that caused traffic between two Geneve endpoints to be unencrypted (bnc#1177511).
- CVE-2020-27673: Fixed an issue where rogue guests could have caused denial of service of Dom0 via high frequency events (XSA-332 bsc#1177411)
- CVE-2020-27675: Fixed a race condition in event handler which may crash dom0 (XSA-331 bsc#1177410).
- CVE-2020-25705: A ICMP global rate limiting side-channel was removed which could lead to e.g. the SADDNS attack (bsc#1175721)

The following non-security bugs were fixed:

- ACPI: dock: fix enum-conversion warning (git-fixes).
- ALSA: bebob: potential info leak in hwdep_read() (git-fixes).
- ALSA: compress_offload: remove redundant initialization (git-fixes).
- ALSA: core: init: use DECLARE_COMPLETION_ONSTACK() macro (git-fixes).
- ALSA: core: pcm: simplify locking for timers (git-fixes).
- ALSA: core: timer: clarify operator precedence (git-fixes).
- ALSA: core: timer: remove redundant assignment (git-fixes).
- ALSA: ctl: Workaround for lockdep warning wrt card->ctl_files_rwlock (git-fixes).
- ALSA: hda: auto_parser: remove shadowed variable declaration (git-fixes).
- ALSA: hda - Do not register a cb func if it is registered already (git-fixes).
- ALSA: hda/realtek - Add mute Led support for HP Elitebook 845 G7 (git-fixes).
- ALSA: hda/realtek: Enable audio jacks of ASUS D700SA with ALC887 (git-fixes).
- ALSA: hda/realtek - The front Mic on a HP machine does not work (git-fixes).
- ALSA: hda: use semicolons rather than commas to separate statements (git-fixes).
- ALSA: mixart: Correct comment wrt obsoleted tasklet usage (git-fixes).
- ALSA: rawmidi: (cosmetic) align function parameters (git-fixes).
- ALSA: seq: oss: Avoid mutex lock for a long-time ioctl (git-fixes).
- ALSA: usb-audio: Add mixer support for Pioneer DJ DJM-250MK2 (git-fixes).
- ALSA: usb-audio: endpoint.c: fix repeated word 'there' (git-fixes).
- ALSA: usb-audio: fix spelling mistake 'Frequence' -> 'Frequency' (git-fixes).
- amd-xgbe: Add a check for an skb in the ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.34.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.34.1", rls:"SLES12.0SP5"))) {
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
