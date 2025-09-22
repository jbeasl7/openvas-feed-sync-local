# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0236.1");
  script_cve_id("CVE-2022-48742", "CVE-2022-49033", "CVE-2022-49035", "CVE-2023-52434", "CVE-2023-52922", "CVE-2024-26976", "CVE-2024-35847", "CVE-2024-36484", "CVE-2024-36883", "CVE-2024-36886", "CVE-2024-38589", "CVE-2024-41013", "CVE-2024-46771", "CVE-2024-47141", "CVE-2024-47666", "CVE-2024-47678", "CVE-2024-47709", "CVE-2024-49925", "CVE-2024-49944", "CVE-2024-50039", "CVE-2024-50143", "CVE-2024-50151", "CVE-2024-50166", "CVE-2024-50199", "CVE-2024-50211", "CVE-2024-50228", "CVE-2024-50256", "CVE-2024-50262", "CVE-2024-50278", "CVE-2024-50280", "CVE-2024-50287", "CVE-2024-50299", "CVE-2024-53057", "CVE-2024-53101", "CVE-2024-53112", "CVE-2024-53136", "CVE-2024-53141", "CVE-2024-53144", "CVE-2024-53146", "CVE-2024-53150", "CVE-2024-53156", "CVE-2024-53157", "CVE-2024-53172", "CVE-2024-53173", "CVE-2024-53179", "CVE-2024-53198", "CVE-2024-53210", "CVE-2024-53214", "CVE-2024-53224", "CVE-2024-53239", "CVE-2024-53240", "CVE-2024-56531", "CVE-2024-56548", "CVE-2024-56551", "CVE-2024-56569", "CVE-2024-56570", "CVE-2024-56587", "CVE-2024-56599", "CVE-2024-5660", "CVE-2024-56603", "CVE-2024-56604", "CVE-2024-56605", "CVE-2024-56606", "CVE-2024-56616", "CVE-2024-56631", "CVE-2024-56642", "CVE-2024-56664", "CVE-2024-56704", "CVE-2024-56724", "CVE-2024-56756", "CVE-2024-57791", "CVE-2024-57849", "CVE-2024-57887", "CVE-2024-57888", "CVE-2024-57892", "CVE-2024-57893", "CVE-2024-8805");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0236-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250236-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1117016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1168202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226694");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230766");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232048");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233050");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233204");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233239");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233469");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233476");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233551");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234087");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234161");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234921");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235009");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235054");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235061");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235249");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235417");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235433");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235480");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235759");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235814");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235918");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235920");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235964");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020196.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2022-48742: rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink() (bsc#1226694).
- CVE-2022-49033: btrfs: qgroup: fix sleep from invalid context bug in btrfs_qgroup_inherit() (bsc#1232045).
- CVE-2022-49035: media: s5p_cec: limit msg.len to CEC_MAX_MSG_SIZE (bsc#1215304).
- CVE-2023-52434: Fixed potential OOBs in smb2_parse_contexts() (bsc#1220148).
- CVE-2023-52922: can: bcm: Fix UAF in bcm_proc_show() (bsc#1233977).
- CVE-2024-26976: KVM: Always flush async #PF workqueue when vCPU is being destroyed (bsc#1223635).
- CVE-2024-35847: irqchip/gic-v3-its: Prevent double free on error (bsc#1224697).
- CVE-2024-36883: net: fix out-of-bounds access in ops_init (bsc#1225725).
- CVE-2024-36886: tipc: fix UAF in error path (bsc#1225730).
- CVE-2024-38589: netrom: fix possible dead-lock in nr_rt_ioctl() (bsc#1226748).
- CVE-2024-41013: xfs: do not walk off the end of a directory data block (bsc#1228405).
- CVE-2024-47141: pinmux: Use sequential access to access desc->pinmux data (bsc#1235708).
- CVE-2024-47666: scsi: pm80xx: Set phy->enable_completion only when we wait for it (bsc#1231453).
- CVE-2024-47678: icmp: change the order of rate limits (bsc#1231854).
- CVE-2024-49944: sctp: set sk_state back to CLOSED if autobind fails in sctp_listen_start (bsc#1232166).
- CVE-2024-50039: kABI: Restore deleted EXPORT_SYMBOL(__qdisc_calculate_pkt_len) (bsc#1231909).
- CVE-2024-50143: udf: fix uninit-value use in udf_get_fileshortad (bsc#1233038).
- CVE-2024-50151: smb: client: fix OOBs when building SMB2_IOCTL request (bsc#1233055).
- CVE-2024-50166: fsl/fman: Fix refcount handling of fman-related devices (bsc#1233050).
- CVE-2024-50199: mm/swapfile: skip HugeTLB pages for unuse_vma (bsc#1233112).
- CVE-2024-50211: udf: refactor inode_bmap() to handle error (bsc#1233096).
- CVE-2024-50256: netfilter: nf_reject_ipv6: fix potential crash in nf_send_reset6() (bsc#1233200).
- CVE-2024-50262: bpf: Fix out-of-bounds write in trie_get_next_key() (bsc#1233239).
- CVE-2024-50287: media: v4l2-tpg: prevent the risk of a division by zero (bsc#1233476).
- CVE-2024-50299: sctp: properly validate chunk size in sctp_sf_ootb() (bsc#1233488).
- CVE-2024-53057: net/sched: stop qdisc_tree_reduce_backlog on TC_H_ROOT (bsc#1233551).
- CVE-2024-53101: fs: Fix uninitialized value issue in from_kuid and from_kgid (bsc#1233769).
- CVE-2024-53141: netfilter: ipset: add missing range check in bitmap_ip_uadt (bsc#1234381).
- CVE-2024-53146: NFSD: Prevent a potential integer overflow (bsc#1234853).
- CVE-2024-53150: ALSA: usb-audio: Fix out of bounds reads when finding clock sources (bsc#1234834).
- CVE-2024-53156: wifi: ath9k: add range check for conn_rsp_epid in htc_connect_service() (bsc#1234846).
- CVE-2024-53157: firmware: arm_scpi: Check the DVFS OPP count ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.244.1", rls:"SLES12.0SP5"))) {
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
