# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.0955.1");
  script_cve_id("CVE-2023-52924", "CVE-2023-52925", "CVE-2024-26708", "CVE-2024-26810", "CVE-2024-40980", "CVE-2024-41055", "CVE-2024-44974", "CVE-2024-45009", "CVE-2024-45010", "CVE-2024-47701", "CVE-2024-49884", "CVE-2024-49950", "CVE-2024-50029", "CVE-2024-50036", "CVE-2024-50073", "CVE-2024-50085", "CVE-2024-50115", "CVE-2024-50142", "CVE-2024-50185", "CVE-2024-50294", "CVE-2024-53123", "CVE-2024-53147", "CVE-2024-53173", "CVE-2024-53176", "CVE-2024-53177", "CVE-2024-53178", "CVE-2024-53226", "CVE-2024-53239", "CVE-2024-56539", "CVE-2024-56548", "CVE-2024-56579", "CVE-2024-56605", "CVE-2024-56633", "CVE-2024-56647", "CVE-2024-56720", "CVE-2024-57889", "CVE-2024-57948", "CVE-2024-57994", "CVE-2025-21636", "CVE-2025-21637", "CVE-2025-21638", "CVE-2025-21639", "CVE-2025-21640", "CVE-2025-21647", "CVE-2025-21665", "CVE-2025-21667", "CVE-2025-21668", "CVE-2025-21673", "CVE-2025-21680", "CVE-2025-21681", "CVE-2025-21684", "CVE-2025-21687", "CVE-2025-21688", "CVE-2025-21689", "CVE-2025-21690", "CVE-2025-21692", "CVE-2025-21697", "CVE-2025-21699", "CVE-2025-21700", "CVE-2025-21705", "CVE-2025-21715", "CVE-2025-21716", "CVE-2025-21719", "CVE-2025-21724", "CVE-2025-21725", "CVE-2025-21728", "CVE-2025-21767", "CVE-2025-21790", "CVE-2025-21795", "CVE-2025-21799", "CVE-2025-21802");
  script_tag(name:"creation_date", value:"2025-03-21 04:06:23 +0000 (Fri, 21 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-21 15:59:44 +0000 (Fri, 21 Feb 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:0955-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0955-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250955-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225742");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227937");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230497");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232299");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232919");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235933");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236682");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236700");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236994");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237325");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237563");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238525");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238877");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020563.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2025:0955-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 RT kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2024-26708: mptcp: fix inconsistent state on fastopen race (bsc#1222672).
- CVE-2024-40980: drop_monitor: replace spin_lock by raw_spin_lock (bsc#1227937).
- CVE-2024-44974: mptcp: pm: avoid possible UaF when selecting endp (bsc#1230235).
- CVE-2024-45009: mptcp: pm: only decrement add_addr_accepted for MPJ req (bsc#1230438).
- CVE-2024-45010: mptcp: pm: only mark 'subflow' endp as available (bsc#1230439).
- CVE-2024-50029: Bluetooth: hci_conn: Fix UAF in hci_enhanced_setup_sync (bsc#1231949).
- CVE-2024-50036: net: do not delay dst_entries_add() in dst_release() (bsc#1231912).
- CVE-2024-50085: mptcp: pm: fix UaF read in mptcp_pm_nl_rm_addr_or_subflow (bsc#1232508).
- CVE-2024-50142: xfrm: validate new SA's prefixlen using SA family when sel.family is unset (bsc#1233028).
- CVE-2024-50185: kABI fix for mptcp: handle consistently DSS corruption (bsc#1233109).
- CVE-2024-50294: rxrpc: Fix missing locking causing hanging calls (bsc#1233483).
- CVE-2024-53123: mptcp: error out earlier on disconnect (bsc#1234070).
- CVE-2024-53147: exfat: fix out-of-bounds access of directory entries (bsc#1234857).
- CVE-2024-53176: smb: During unmount, ensure all cached dir instances drop their dentry (bsc#1234894).
- CVE-2024-53177: smb: prevent use-after-free due to open_cached_dir error paths (bsc#1234896).
- CVE-2024-53178: smb: Do not leak cfid when reconnect races with open_cached_dir (bsc#1234895).
- CVE-2024-56633: selftests/bpf: Add apply_bytes test to test_txmsg_redir_wait_sndmem in test_sockmap (bsc#1235485).
- CVE-2024-56647: net: Fix icmp host relookup triggering ip_rt_bug (bsc#1235435).
- CVE-2024-56720: bpf, sockmap: Several fixes to bpf_msg_pop_data (bsc#1235592).
- CVE-2024-57994: ptr_ring: do not block hard interrupts in ptr_ring_resize_multiple() (bsc#1237901).
- CVE-2025-21636: sctp: sysctl: plpmtud_probe_interval: avoid using current->nsproxy (bsc#1236113).
- CVE-2025-21637: sctp: sysctl: udp_port: avoid using current->nsproxy (bsc#1236114).
- CVE-2025-21638: sctp: sysctl: auth_enable: avoid using current->nsproxy (bsc#1236115).
- CVE-2025-21639: sctp: sysctl: rto_min/max: avoid using current->nsproxy (bsc#1236122).
- CVE-2025-21640: sctp: sysctl: cookie_hmac_alg: avoid using current->nsproxy (bsc#1236123).
- CVE-2025-21647: sched: sch_cake: add bounds checks to host bulk flow fairness counts (bsc#1236133).
- CVE-2025-21665: filemap: avoid truncating 64-bit offset to 32 bits (bsc#1236684).
- CVE-2025-21667: iomap: avoid avoid truncating 64-bit offset to 32 bits (bsc#1236681).
- CVE-2025-21668: pmdomain: imx8mp-blk-ctrl: add missing loop break condition (bsc#1236682).
- CVE-2025-21673: smb: client: fix double free of TCP_Server_Info::hostname (bsc#1236689).
- CVE-2025-21680: pktgen: Avoid out-of-bounds access in get_imix_entries ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra", rpm:"kernel-rt-extra~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch-devel", rpm:"kernel-rt-livepatch-devel~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional", rpm:"kernel-rt-optional~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso", rpm:"kernel-rt-vdso~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso", rpm:"kernel-rt_debug-vdso~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt", rpm:"kselftests-kmp-rt~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt", rpm:"reiserfs-kmp-rt~6.4.0~150600.10.29.1", rls:"openSUSELeap15.6"))) {
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
