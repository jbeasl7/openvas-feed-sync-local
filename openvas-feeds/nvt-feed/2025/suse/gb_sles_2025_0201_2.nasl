# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0201.2");
  script_cve_id("CVE-2021-47202", "CVE-2022-36280", "CVE-2022-48742", "CVE-2022-49033", "CVE-2022-49035", "CVE-2023-1382", "CVE-2023-33951", "CVE-2023-33952", "CVE-2023-52920", "CVE-2024-24860", "CVE-2024-26886", "CVE-2024-26924", "CVE-2024-36915", "CVE-2024-42232", "CVE-2024-44934", "CVE-2024-47666", "CVE-2024-47678", "CVE-2024-49944", "CVE-2024-49952", "CVE-2024-50018", "CVE-2024-50143", "CVE-2024-50154", "CVE-2024-50166", "CVE-2024-50181", "CVE-2024-50202", "CVE-2024-50211", "CVE-2024-50256", "CVE-2024-50262", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50280", "CVE-2024-50296", "CVE-2024-53051", "CVE-2024-53055", "CVE-2024-53056", "CVE-2024-53064", "CVE-2024-53072", "CVE-2024-53090", "CVE-2024-53095", "CVE-2024-53101", "CVE-2024-53113", "CVE-2024-53114", "CVE-2024-53119", "CVE-2024-53120", "CVE-2024-53122", "CVE-2024-53125", "CVE-2024-53130", "CVE-2024-53131", "CVE-2024-53142", "CVE-2024-53146", "CVE-2024-53150", "CVE-2024-53156", "CVE-2024-53157", "CVE-2024-53158", "CVE-2024-53161", "CVE-2024-53162", "CVE-2024-53173", "CVE-2024-53179", "CVE-2024-53206", "CVE-2024-53210", "CVE-2024-53213", "CVE-2024-53214", "CVE-2024-53239", "CVE-2024-53240", "CVE-2024-53241", "CVE-2024-56539", "CVE-2024-56548", "CVE-2024-56549", "CVE-2024-56570", "CVE-2024-56571", "CVE-2024-56575", "CVE-2024-56598", "CVE-2024-56604", "CVE-2024-56605", "CVE-2024-56619", "CVE-2024-56755", "CVE-2024-8805");
  script_tag(name:"creation_date", value:"2025-03-13 04:07:10 +0000 (Thu, 13 Mar 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0201-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0201-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250201-2.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190358");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205521");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215523");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228190");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230422");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232419");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233468");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233547");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233550");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233558");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234077");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234219");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234650");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235507");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-March/020501.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0201-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-36280: Fixed out-of-bounds memory access vulnerability found in vmwgfx driver (bsc#1203332).
- CVE-2022-48742: rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink() (bsc#1226694).
- CVE-2022-49033: btrfs: qgroup: fix sleep from invalid context bug in btrfs_qgroup_inherit() (bsc#1232045).
- CVE-2023-1382: Fixed denial of service in tipc_conn_close (bsc#1209288).
- CVE-2023-33951: Fixed a race condition that could have led to an information disclosure inside the vmwgfx driver (bsc#1211593).
- CVE-2023-33952: Fixed a double free that could have led to a local privilege escalation inside the vmwgfx driver (bsc#1211595).
- CVE-2023-52920: bpf: support non-r10 register spill/fill to/from stack in precision tracking (bsc#1232823).
- CVE-2024-26886: Bluetooth: af_bluetooth: Fix deadlock (bsc#1223044).
- CVE-2024-26924: scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up() (bsc#1225820).
- CVE-2024-36915: nfc: llcp: fix nfc_llcp_setsockopt() unsafe copies (bsc#1225758).
- CVE-2024-44934: net: bridge: mcast: wait for previous gc cycles when removing port (bsc#1229809).
- CVE-2024-47666: scsi: pm80xx: Set phy->enable_completion only when we wait for it (bsc#1231453).
- CVE-2024-47678: icmp: change the order of rate limits (bsc#1231854).
- CVE-2024-49944: sctp: set sk_state back to CLOSED if autobind fails in sctp_listen_start (bsc#1232166).
- CVE-2024-49952: netfilter: nf_tables: prevent nf_skb_duplicated corruption (bsc#1232157).
- CVE-2024-50018: net: napi: Prevent overflow of napi_defer_hard_irqs (bsc#1232419).
- CVE-2024-50143: udf: fix uninit-value use in udf_get_fileshortad (bsc#1233038).
- CVE-2024-50166: fsl/fman: Fix refcount handling of fman-related devices (bsc#1233050).
- CVE-2024-50181: clk: imx: Remove CLK_SET_PARENT_GATE for DRAM mux for i.MX7D (bsc#1233127).
- CVE-2024-50202: nilfs2: propagate directory read errors from nilfs_find_entry() (bsc#1233324).
- CVE-2024-50211: udf: refactor inode_bmap() to handle error (bsc#1233096).
- CVE-2024-50256: netfilter: nf_reject_ipv6: fix potential crash in nf_send_reset6() (bsc#1233200).
- CVE-2024-50262: bpf: Fix out-of-bounds write in trie_get_next_key() (bsc#1233239).
- CVE-2024-50278, CVE-2024-50280: dm cache: fix flushing uninitialized delayed_work on cache_ctr error (bsc#1233467 bsc#1233469).
- CVE-2024-50278: dm cache: fix potential out-of-bounds access on the first resume (bsc#1233467).
- CVE-2024-50279: dm cache: fix out-of-bounds access to the dirty bitset when resizing (bsc#1233468).
- CVE-2024-50296: net: hns3: fix kernel crash when uninstalling driver (bsc#1233485).
- CVE-2024-53051: drm/i915/hdcp: Add encoder check in intel_hdcp_get_capability (bsc#1233547).
- CVE-2024-53055: wifi: iwlwifi: mvm: fix 6 GHz scan construction (bsc#1233550).
- ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.91.1.150500.6.41.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.91.1", rls:"SLES15.0SP5"))) {
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
