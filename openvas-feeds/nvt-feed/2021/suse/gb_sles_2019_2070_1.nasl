# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2070.1");
  script_cve_id("CVE-2018-20855", "CVE-2019-1125", "CVE-2019-11810", "CVE-2019-13631", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-07 18:42:14 +0000 (Tue, 07 May 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2070-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2070-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192070-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1051510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1055117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1111666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1112374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1123080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1127611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1134399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1135642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136462");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1136896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137534");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1137827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1138874");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1139619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140676");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140972");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1140992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141402");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142052");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142359");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143507");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2019-August/005788.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2070-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-20855: An issue was discovered in the Linux kernel In create_qp_common in drivers/infiniband/hw/mlx5/qp.c, mlx5_ib_create_qp_resp was never initialized, resulting in a leak of stack memory to userspace(bsc#1143045).
- CVE-2019-1125: Exclude ATOMs from speculation through SWAPGS (bsc#1139358).
- CVE-2019-14283: In the Linux kernel, set_geometry in drivers/block/floppy.c did not validate the sect and head fields, as demonstrated by an integer overflow and out-of-bounds read. It could be triggered by an unprivileged local user when a floppy disk was inserted. NOTE: QEMU creates the floppy device by default. (bnc#1143191)
- CVE-2019-11810: An issue was discovered in the Linux kernel A NULL pointer dereference could occur when megasas_create_frame_pool() failed in megasas_alloc_cmds() in drivers/scsi/megaraid/megaraid_sas_base.c. This caused a Denial of Service, related to a use-after-free (bnc#1134399).
- CVE-2019-13648: In the Linux kernel on the powerpc platform, when hardware transactional memory was disabled, a local user could cause a denial of service (TM Bad Thing exception and system crash) via a sigreturn() system call that sent a crafted signal frame. (bnc#1142254)
- CVE-2019-13631: In parse_hid_report_descriptor in drivers/input/tablet/gtco.c in the Linux kernel, a malicious USB device could send an HID report that triggered an out-of-bounds write during generation of debugging messages. (bnc#1142023)

The following non-security bugs were fixed:
- Correct the CVE and bug reference for a floppy security fix (CVE-2019-14284,bsc#1143189) A dedicated CVE was already assigned
- acpi/nfit: Always dump _DSM output payload (bsc#1142351).
- Add back sibling paca poiter to paca (bsc#1055117).
- Add support for crct10dif-vpmsum ().
- af_unix: remove redundant lockdep class (git-fixes).
- alsa: compress: Be more restrictive about when a drain is allowed (bsc#1051510).
- alsa: compress: Do not allow partial drain operations on capture streams (bsc#1051510).
- alsa: compress: Fix regression on compressed capture streams (bsc#1051510).
- alsa: compress: Prevent bypasses of set_params (bsc#1051510).
- alsa: hda - Add a conexant codec entry to let mute led work (bsc#1051510).
- alsa: hda - Do not resume forcibly i915 HDMI/DP codec (bsc#1111666).
- alsa: hda - Fix intermittent CORB/RIRB stall on Intel chips (bsc#1111666).
- alsa: hda/hdmi - Fix i915 reverse port/pin mapping (bsc#1111666).
- alsa: hda/hdmi - Remove duplicated define (bsc#1111666).
- alsa: hda - Optimize resume for codecs without jack detection (bsc#1111666).
- alsa: hda/realtek: apply ALC891 headset fixup to one Dell machine (bsc#1051510).
- alsa: hda/realtek - Fixed Headphone Mic can't record on Dell platform (bsc#1051510).
- alsa: hda/realtek - Headphone Mic can't ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~6.23.1", rls:"SLES12.0SP4"))) {
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
