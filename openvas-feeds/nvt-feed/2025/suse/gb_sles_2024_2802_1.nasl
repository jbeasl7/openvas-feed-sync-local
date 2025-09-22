# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2802.1");
  script_cve_id("CVE-2023-38417", "CVE-2023-47210", "CVE-2023-51780", "CVE-2023-52435", "CVE-2023-52472", "CVE-2023-52751", "CVE-2023-52775", "CVE-2024-25741", "CVE-2024-26615", "CVE-2024-26623", "CVE-2024-26633", "CVE-2024-26635", "CVE-2024-26636", "CVE-2024-26641", "CVE-2024-26663", "CVE-2024-26665", "CVE-2024-26691", "CVE-2024-26734", "CVE-2024-26785", "CVE-2024-26826", "CVE-2024-26863", "CVE-2024-26944", "CVE-2024-27012", "CVE-2024-27015", "CVE-2024-27016", "CVE-2024-27019", "CVE-2024-27020", "CVE-2024-27025", "CVE-2024-27064", "CVE-2024-27065", "CVE-2024-27402", "CVE-2024-27404", "CVE-2024-35805", "CVE-2024-35853", "CVE-2024-35854", "CVE-2024-35890", "CVE-2024-35893", "CVE-2024-35899", "CVE-2024-35908", "CVE-2024-35934", "CVE-2024-35942", "CVE-2024-36003", "CVE-2024-36004", "CVE-2024-36889", "CVE-2024-36901", "CVE-2024-36902", "CVE-2024-36909", "CVE-2024-36910", "CVE-2024-36911", "CVE-2024-36912", "CVE-2024-36913", "CVE-2024-36914", "CVE-2024-36922", "CVE-2024-36930", "CVE-2024-36940", "CVE-2024-36941", "CVE-2024-36942", "CVE-2024-36944", "CVE-2024-36946", "CVE-2024-36947", "CVE-2024-36949", "CVE-2024-36950", "CVE-2024-36951", "CVE-2024-36955", "CVE-2024-36959", "CVE-2024-36974", "CVE-2024-38558", "CVE-2024-38586", "CVE-2024-38598", "CVE-2024-38604", "CVE-2024-38659", "CVE-2024-39276", "CVE-2024-39468", "CVE-2024-39472", "CVE-2024-39473", "CVE-2024-39474", "CVE-2024-39475", "CVE-2024-39479", "CVE-2024-39481", "CVE-2024-39482", "CVE-2024-39487", "CVE-2024-39490", "CVE-2024-39494", "CVE-2024-39496", "CVE-2024-39498", "CVE-2024-39502", "CVE-2024-39504", "CVE-2024-39507", "CVE-2024-40901", "CVE-2024-40906", "CVE-2024-40908", "CVE-2024-40919", "CVE-2024-40923", "CVE-2024-40925", "CVE-2024-40928", "CVE-2024-40931", "CVE-2024-40935", "CVE-2024-40937", "CVE-2024-40940", "CVE-2024-40947", "CVE-2024-40948", "CVE-2024-40953", "CVE-2024-40960", "CVE-2024-40961", "CVE-2024-40966", "CVE-2024-40970", "CVE-2024-40972", "CVE-2024-40975", "CVE-2024-40979", "CVE-2024-40998", "CVE-2024-40999", "CVE-2024-41006", "CVE-2024-41011", "CVE-2024-41013", "CVE-2024-41014", "CVE-2024-41017", "CVE-2024-41090", "CVE-2024-41091");
  script_tag(name:"creation_date", value:"2025-06-04 14:43:37 +0000 (Wed, 04 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-06 13:19:10 +0000 (Fri, 06 Sep 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2802-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2802-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242802-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215587");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218442");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221656");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223731");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225272");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225601");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225805");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225830");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225835");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225847");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226502");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226519");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226750");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226915");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227383");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227736");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227789");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227800");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227803");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227862");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227910");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227913");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227926");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228090");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228408");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228417");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-August/019133.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:2802-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2023-47210: wifi: iwlwifi: bump FW API to 90 for BZ/SC devices (bsc#1225601, bsc#1225600).
- CVE-2023-52435: net: prevent mss overflow in skb_segment() (bsc#1220138).
- CVE-2023-52751: smb: client: fix use-after-free in smb2_query_info_compound() (bsc#1225489).
- CVE-2023-52775: net/smc: avoid data corruption caused by decline (bsc#1225088).
- CVE-2024-26615: net/smc: fix illegal rmb_desc access in SMC-D connection dump (bsc#1220942).
- CVE-2024-26623: pds_core: Prevent race issues involving the adminq (bsc#1221057).
- CVE-2024-26633: ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim() (bsc#1221647).
- CVE-2024-26635: llc: Drop support for ETH_P_TR_802_2 (bsc#1221656).
- CVE-2024-26636: llc: make llc_ui_sendmsg() more robust against bonding changes (bsc#1221659).
- CVE-2024-26641: ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv() (bsc#1221654).
- CVE-2024-26663: tipc: Check the bearer type before calling tipc_udp_nl_bearer_add() (bsc#1222326).
- CVE-2024-26665: tunnels: fix out of bounds access when building IPv6 PMTU error (bsc#1222328).
- CVE-2024-26691: KVM: arm64: Fix circular locking dependency (bsc#1222463).
- CVE-2024-26734: devlink: fix possible use-after-free and memory leaks in devlink_init() (bsc#1222438).
- CVE-2024-26785: iommufd: Fix protection fault in iommufd_test_syz_conv_iova (bsc#1222779).
- CVE-2024-26826: mptcp: fix data re-injection from stale subflow (bsc#1223010).
- CVE-2024-26863: hsr: Fix uninit-value access in hsr_get_node() (bsc#1223021).
- CVE-2024-26944: btrfs: zoned: fix lock ordering in btrfs_zone_activate() (bsc#1223731).
- CVE-2024-27012: netfilter: nf_tables: restore set elements when delete set fails (bsc#1223804).
- CVE-2024-27015: netfilter: flowtable: incorrect pppoe tuple (bsc#1223806).
- CVE-2024-27016: netfilter: flowtable: validate pppoe header (bsc#1223807).
- CVE-2024-27019: netfilter: nf_tables: Fix potential data-race in __nft_obj_type_get() (bsc#1223813)
- CVE-2024-27020: netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (bsc#1223815)
- CVE-2024-27025: nbd: null check for nla_nest_start (bsc#1223778)
- CVE-2024-27064: netfilter: nf_tables: Fix a memory leak in nf_tables_updchain (bsc#1223740).
- CVE-2024-27065: netfilter: nf_tables: do not compare internal table flags on updates (bsc#1223836).
- CVE-2024-27402: phonet/pep: fix racy skb_queue_empty() use (bsc#1224414).
- CVE-2024-27404: mptcp: fix data races on remote_id (bsc#1224422)
- CVE-2024-35805: dm snapshot: fix lockup in dm_exception_table_exit (bsc#1224743).
- CVE-2024-35853: mlxsw: spectrum_acl_tcam: Fix memory leak during rehash (bsc#1224604).
- CVE-2024-35854: Fixed possible use-after-free during rehash (bsc#1224636).
- CVE-2024-35890: gro: fix ownership transfer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~6.4.0~150600.23.17.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~6.4.0~150600.23.17.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~6.4.0~150600.23.17.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~6.4.0~150600.23.17.1.150600.12.6.2", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~6.4.0~150600.23.17.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.4.0~150600.23.17.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~6.4.0~150600.23.17.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~6.4.0~150600.23.17.1", rls:"SLES15.0SP6"))) {
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
