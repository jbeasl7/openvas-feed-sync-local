# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02249.1");
  script_cve_id("CVE-2023-52888", "CVE-2024-26831", "CVE-2024-49568", "CVE-2024-50106", "CVE-2024-56613", "CVE-2024-56699", "CVE-2024-57982", "CVE-2024-58053", "CVE-2025-21658", "CVE-2025-21720", "CVE-2025-21868", "CVE-2025-21898", "CVE-2025-21899", "CVE-2025-21920", "CVE-2025-21938", "CVE-2025-21959", "CVE-2025-21997", "CVE-2025-22035", "CVE-2025-22083", "CVE-2025-22111", "CVE-2025-22113", "CVE-2025-22120", "CVE-2025-23155", "CVE-2025-37738", "CVE-2025-37743", "CVE-2025-37752", "CVE-2025-37756", "CVE-2025-37757", "CVE-2025-37786", "CVE-2025-37800", "CVE-2025-37801", "CVE-2025-37811", "CVE-2025-37844", "CVE-2025-37859", "CVE-2025-37862", "CVE-2025-37865", "CVE-2025-37874", "CVE-2025-37884", "CVE-2025-37909", "CVE-2025-37917", "CVE-2025-37921", "CVE-2025-37923", "CVE-2025-37927", "CVE-2025-37933", "CVE-2025-37936", "CVE-2025-37938", "CVE-2025-37945", "CVE-2025-37946", "CVE-2025-37961", "CVE-2025-37967", "CVE-2025-37968", "CVE-2025-37973", "CVE-2025-37987", "CVE-2025-37992", "CVE-2025-37994", "CVE-2025-37995", "CVE-2025-37997", "CVE-2025-37998", "CVE-2025-38000", "CVE-2025-38001", "CVE-2025-38003", "CVE-2025-38004", "CVE-2025-38005", "CVE-2025-38007", "CVE-2025-38009", "CVE-2025-38010", "CVE-2025-38011", "CVE-2025-38013", "CVE-2025-38014", "CVE-2025-38015", "CVE-2025-38018", "CVE-2025-38020", "CVE-2025-38022", "CVE-2025-38023", "CVE-2025-38024", "CVE-2025-38027", "CVE-2025-38031", "CVE-2025-38040", "CVE-2025-38043", "CVE-2025-38044", "CVE-2025-38045", "CVE-2025-38053", "CVE-2025-38057", "CVE-2025-38059", "CVE-2025-38060", "CVE-2025-38065", "CVE-2025-38068", "CVE-2025-38072", "CVE-2025-38077", "CVE-2025-38078", "CVE-2025-38079", "CVE-2025-38080", "CVE-2025-38081", "CVE-2025-38083");
  script_tag(name:"creation_date", value:"2025-07-10 08:17:16 +0000 (Thu, 10 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-11 13:13:02 +0000 (Fri, 11 Apr 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02249-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02249-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502249-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151679");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151680");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223008");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240686");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241278");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243342");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243475");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243538");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243542");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244145");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244176");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244737");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245083");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245431");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245455");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040634.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2025:02249-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 Azure kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2023-52888: media: mediatek: vcodec: Only free buffer VA that is not NULL (bsc#1228557).
- CVE-2024-49568: net/smc: check v2_ext_offset/eid_cnt/ism_gid_cnt when receiving proposal msg (bsc#1235728).
- CVE-2024-57982: xfrm: state: fix out-of-bounds read during lookup (bsc#1237913).
- CVE-2024-58053: rxrpc: Fix handling of received connection abort (bsc#1238982).
- CVE-2025-21720: xfrm: delete intermediate secpath entry in packet offload mode (bsc#1238859).
- CVE-2025-21868: kABI workaround for adding an header (bsc#1240180).
- CVE-2025-21898: ftrace: Avoid potential division by zero in function_stat_show() (bsc#1240610).
- CVE-2025-21899: tracing: Fix bad hist from corrupting named_triggers list (bsc#1240577).
- CVE-2025-21920: vlan: enforce underlying device type (bsc#1240686).
- CVE-2025-21938: mptcp: fix 'scheduling while atomic' in mptcp_pm_nl_append_new_local_addr (bsc#1240723).
- CVE-2025-21959: netfilter: nf_conncount: Fully initialize struct nf_conncount_tuple in insert_tree() (bsc#1240814).
- CVE-2025-21997: xsk: fix an integer overflow in xp_create_and_assign_umem() (bsc#1240823).
- CVE-2025-22035: tracing: Fix use-after-free in print_graph_function_flags during tracer switching (bsc#1241544).
- CVE-2025-22111: kABI fix for net: Remove RTNL dance for SIOCBRADDIF and SIOCBRDELIF (bsc#1241572).
- CVE-2025-22113: ext4: define ext4_journal_destroy wrapper (bsc#1241617).
- CVE-2025-23155: net: stmmac: Fix accessing freed irq affinity_hint (bsc#1242573).
- CVE-2025-37738: ext4: ignore xattrs past end (bsc#1242846).
- CVE-2025-37743: wifi: ath12k: Avoid memory leak while enabling statistics (bsc#1242163).
- CVE-2025-37752: net_sched: sch_sfq: move the limit validation (bsc#1242504).
- CVE-2025-37756: net: tls: explicitly disallow disconnect (bsc#1242515).
- CVE-2025-37757: tipc: fix memory leak in tipc_link_xmit (bsc#1242521).
- CVE-2025-37786: net: dsa: free routing table on probe failure (bsc#1242725).
- CVE-2025-37800: driver core: fix potential NULL pointer dereference in dev_uevent() (bsc#1242849).
- CVE-2025-37801: spi: spi-imx: Add check for spi_imx_setupxfer() (bsc#1242850).
- CVE-2025-37811: usb: chipidea: ci_hdrc_imx: fix usbmisc handling (bsc#1242907).
- CVE-2025-37844: cifs: avoid NULL pointer dereference in dbg call (bsc#1242946).
- CVE-2025-37859: page_pool: avoid infinite loop to schedule delayed worker (bsc#1243051).
- CVE-2025-37862: HID: pidff: Fix null pointer dereference in pidff_find_fields (bsc#1242982).
- CVE-2025-37865: net: dsa: mv88e6xxx: fix -ENOENT when deleting VLANs and MST is unsupported (bsc#1242954).
- CVE-2025-37874: net: ngbe: fix memory leak in ngbe_probe() error path (bsc#1242940).
- CVE-2025-37884: bpf: Fix deadlock between rcu_tasks_trace and event_mutex (bsc#1243060).
- CVE-2025-37909: ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-azure", rpm:"cluster-md-kmp-azure~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-azure", rpm:"dlm-kmp-azure~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-azure", rpm:"gfs2-kmp-azure~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-extra", rpm:"kernel-azure-extra~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-optional", rpm:"kernel-azure-optional~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-vdso", rpm:"kernel-azure-vdso~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-azure", rpm:"kselftests-kmp-azure~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-azure", rpm:"ocfs2-kmp-azure~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-azure", rpm:"reiserfs-kmp-azure~6.4.0~150600.8.43.1", rls:"openSUSELeap15.6"))) {
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
