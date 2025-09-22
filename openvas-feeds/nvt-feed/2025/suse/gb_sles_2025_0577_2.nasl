# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0577.2");
  script_cve_id("CVE-2024-26758", "CVE-2024-26943", "CVE-2024-36898", "CVE-2024-38599", "CVE-2024-41047", "CVE-2024-45019", "CVE-2024-46858", "CVE-2024-50051", "CVE-2024-50136", "CVE-2024-50142", "CVE-2024-50151", "CVE-2024-50195", "CVE-2024-50199", "CVE-2024-50210", "CVE-2024-50275", "CVE-2024-50299", "CVE-2024-53095", "CVE-2024-53103", "CVE-2024-53104", "CVE-2024-53112", "CVE-2024-53121", "CVE-2024-53127", "CVE-2024-53129", "CVE-2024-53138", "CVE-2024-53141", "CVE-2024-53144", "CVE-2024-53148", "CVE-2024-53151", "CVE-2024-53166", "CVE-2024-53169", "CVE-2024-53171", "CVE-2024-53174", "CVE-2024-53177", "CVE-2024-53208", "CVE-2024-53209", "CVE-2024-53215", "CVE-2024-53217", "CVE-2024-53224", "CVE-2024-53227", "CVE-2024-53229", "CVE-2024-53690", "CVE-2024-54680", "CVE-2024-55916", "CVE-2024-56531", "CVE-2024-56532", "CVE-2024-56533", "CVE-2024-56557", "CVE-2024-56558", "CVE-2024-56562", "CVE-2024-56567", "CVE-2024-56588", "CVE-2024-56595", "CVE-2024-56596", "CVE-2024-56597", "CVE-2024-56600", "CVE-2024-56601", "CVE-2024-56602", "CVE-2024-56623", "CVE-2024-56629", "CVE-2024-56631", "CVE-2024-56642", "CVE-2024-56644", "CVE-2024-56645", "CVE-2024-56648", "CVE-2024-56650", "CVE-2024-56658", "CVE-2024-56661", "CVE-2024-56664", "CVE-2024-56678", "CVE-2024-56681", "CVE-2024-56698", "CVE-2024-56701", "CVE-2024-56704", "CVE-2024-56722", "CVE-2024-56739", "CVE-2024-56745", "CVE-2024-56747", "CVE-2024-56754", "CVE-2024-56756", "CVE-2024-56759", "CVE-2024-56765", "CVE-2024-56776", "CVE-2024-56777", "CVE-2024-56778", "CVE-2024-57791", "CVE-2024-57792", "CVE-2024-57793", "CVE-2024-57798", "CVE-2024-57849", "CVE-2024-57850", "CVE-2024-57876", "CVE-2024-57893", "CVE-2024-57897", "CVE-2024-8805");
  script_tag(name:"creation_date", value:"2025-03-13 04:07:10 +0000 (Thu, 13 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0577-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0577-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250577-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234683");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235059");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235230");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235451");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235458");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235812");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236628");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020500.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0577-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-36898: gpiolib: cdev: fix uninitialised kfifo (bsc#1225736).
- CVE-2024-46858: mptcp: pm: Fix uaf in __timer_delete_sync (bsc#1231088).
- CVE-2024-50142: xfrm: validate new SA's prefixlen using SA family when sel.family is unset (bsc#1233028).
- CVE-2024-50151: smb: client: fix OOBs when building SMB2_IOCTL request (bsc#1233055).
- CVE-2024-50199: mm/swapfile: skip HugeTLB pages for unuse_vma (bsc#1233112).
- CVE-2024-50299: sctp: properly validate chunk size in sctp_sf_ootb() (bsc#1233488).
- CVE-2024-53104: media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format (bsc#1234025).
- CVE-2024-53141: netfilter: ipset: add missing range check in bitmap_ip_uadt (bsc#1234381).
- CVE-2024-53166: block, bfq: fix bfqq uaf in bfq_limit_depth() (bsc#1234884).
- CVE-2024-53177: smb: prevent use-after-free due to open_cached_dir error paths (bsc#1234896).
- CVE-2024-53209: bnxt_en: Fix receive ring space parameters when XDP is active (bsc#1235002).
- CVE-2024-53227: scsi: bfa: Fix use-after-free in bfad_im_module_exit() (bsc#1235011).
- CVE-2024-56588: scsi: hisi_sas: Create all dump files during debugfs initialization (bsc#1235123).
- CVE-2024-56600: net: inet6: do not leave a dangling sk pointer in inet6_create() (bsc#1235217).
- CVE-2024-56601: net: inet: do not leave a dangling sk pointer in inet_create() (bsc#1235230).
- CVE-2024-56602: net: ieee802154: do not leave a dangling sk pointer in ieee802154_create() (bsc#1235521).
- CVE-2024-56623: scsi: qla2xxx: Fix use after free on unload (bsc#1235466).
- CVE-2024-56631: scsi: sg: Fix slab-use-after-free read in sg_release() (bsc#1235480).
- CVE-2024-56642: tipc: Fix use-after-free of kernel socket in cleanup_bearer() (bsc#1235433).
- CVE-2024-56645: can: j1939: j1939_session_new(): fix skb reference counting (bsc#1235134).
- CVE-2024-56648: net: hsr: avoid potential out-of-bound access in fill_frame_info() (bsc#1235451).
- CVE-2024-56650: netfilter: x_tables: fix LED ID check in led_tg_check() (bsc#1235430).
- CVE-2024-56658: net: defer final 'struct net' free in netns dismantle (bsc#1235441).
- CVE-2024-56664: bpf, sockmap: Fix race between element replace and close() (bsc#1235249).
- CVE-2024-56704: 9p/xen: fix release of IRQ (bsc#1235584).
- CVE-2024-56747: scsi: qedi: Fix a possible memory leak in qedi_alloc_and_init_sb() (bsc#1234934).
- CVE-2024-56759: btrfs: fix use-after-free when COWing tree bock and tracing is enabled (bsc#1235645).
- CVE-2024-57791: net/smc: check return value of sock_recvmsg when draining clc data (bsc#1235759).
- CVE-2024-57792: power: supply: gpio-charger: Fix set charge current limits (bsc#1235764).
- CVE-2024-57793: virt: tdx-guest: Just leak decrypted memory on unrecoverable errors (bsc#1235768).
- CVE-2024-57798: drm/dp_mst: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.94.1.150500.6.43.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.94.1", rls:"SLES15.0SP5"))) {
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
