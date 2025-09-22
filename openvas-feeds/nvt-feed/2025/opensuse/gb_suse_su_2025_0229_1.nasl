# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856981");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2020-12770", "CVE-2021-34556", "CVE-2021-35477", "CVE-2021-38160", "CVE-2021-47202", "CVE-2022-36280", "CVE-2022-48742", "CVE-2022-49033", "CVE-2022-49035", "CVE-2023-1382", "CVE-2023-33951", "CVE-2023-33952", "CVE-2023-52920", "CVE-2024-24860", "CVE-2024-26886", "CVE-2024-26924", "CVE-2024-36915", "CVE-2024-42232", "CVE-2024-44934", "CVE-2024-47666", "CVE-2024-47678", "CVE-2024-49944", "CVE-2024-49952", "CVE-2024-50018", "CVE-2024-50143", "CVE-2024-50154", "CVE-2024-50166", "CVE-2024-50181", "CVE-2024-50202", "CVE-2024-50211", "CVE-2024-50256", "CVE-2024-50262", "CVE-2024-50278", "CVE-2024-50279", "CVE-2024-50280", "CVE-2024-50296", "CVE-2024-53051", "CVE-2024-53055", "CVE-2024-53056", "CVE-2024-53064", "CVE-2024-53072", "CVE-2024-53090", "CVE-2024-53101", "CVE-2024-53113", "CVE-2024-53114", "CVE-2024-53119", "CVE-2024-53120", "CVE-2024-53122", "CVE-2024-53125", "CVE-2024-53130", "CVE-2024-53131", "CVE-2024-53142", "CVE-2024-53146", "CVE-2024-53150", "CVE-2024-53156", "CVE-2024-53157", "CVE-2024-53158", "CVE-2024-53161", "CVE-2024-53162", "CVE-2024-53173", "CVE-2024-53179", "CVE-2024-53206", "CVE-2024-53210", "CVE-2024-53213", "CVE-2024-53214", "CVE-2024-53239", "CVE-2024-53240", "CVE-2024-53241", "CVE-2024-56539", "CVE-2024-56548", "CVE-2024-56549", "CVE-2024-56570", "CVE-2024-56571", "CVE-2024-56575", "CVE-2024-56598", "CVE-2024-56604", "CVE-2024-56605", "CVE-2024-56619", "CVE-2024-56755", "CVE-2024-8805");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-20 18:05:47 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"creation_date", value:"2025-01-25 05:00:09 +0000 (Sat, 25 Jan 2025)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2025:0229-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0229-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QKZ7BYAGH4HRY63AMXDJEMZVBO2NHQLZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2025:0229-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 RT kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

    * CVE-2022-36280: Fixed out-of-bounds memory access vulnerability found in
      vmwgfx driver (bsc#1203332).
    * CVE-2022-48742: rtnetlink: make sure to refresh master_dev/m_ops in
      __rtnl_newlink() (bsc#1226694).
    * CVE-2022-49033: btrfs: qgroup: fix sleep from invalid context bug in
      btrfs_qgroup_inherit() (bsc#1232045).
    * CVE-2023-1382: Fixed denial of service in tipc_conn_close (bsc#1209288).
    * CVE-2023-52920: bpf: support non-r10 register spill/fill to/from stack in
      precision tracking (bsc#1232823).
    * CVE-2024-26886: Bluetooth: af_bluetooth: Fix deadlock (bsc#1223044).
    * CVE-2024-26924: scsi: lpfc: Release hbalock before calling
      lpfc_worker_wake_up() (bsc#1225820).
    * CVE-2024-36915: nfc: llcp: fix nfc_llcp_setsockopt() unsafe copies
      (bsc#1225758).
    * CVE-2024-44934: net: bridge: mcast: wait for previous gc cycles when
      removing port (bsc#1229809).
    * CVE-2024-47666: scsi: pm80xx: Set phy->enable_completion only when we wait
      for it (bsc#1231453).
    * CVE-2024-47678: icmp: change the order of rate limits (bsc#1231854).
    * CVE-2024-49944: sctp: set sk_state back to CLOSED if autobind fails in
      sctp_listen_start (bsc#1232166).
    * CVE-2024-49952: netfilter: nf_tables: prevent nf_skb_duplicated corruption
      (bsc#1232157).
    * CVE-2024-50018: net: napi: Prevent overflow of napi_defer_hard_irqs
      (bsc#1232419).
    * CVE-2024-50143: udf: fix uninit-value use in udf_get_fileshortad
      (bsc#1233038).
    * CVE-2024-50166: fsl/fman: Fix refcount handling of fman-related devices
      (bsc#1233050).
    * CVE-2024-50181: clk: imx: Remove CLK_SET_PARENT_GATE for DRAM mux for i.MX7D
      (bsc#1233127).
    * CVE-2024-50202: nilfs2: propagate directory read errors from
      nilfs_find_entry() (bsc#1233324).
    * CVE-2024-50211: udf: refactor inode_bmap() to handle error (bsc#1233096).
    * CVE-2024-50256: netfilter: nf_reject_ipv6: fix potential crash in
      nf_send_reset6() (bsc#1233200).
    * CVE-2024-50262: bpf: Fix out-of-bounds write in trie_get_next_key()
      (bsc#1233239).
    * CVE-2024-50296: net: hns3: fix kernel crash when uninstalling driver
      (bsc#1233485).
    * CVE-2024-53051: drm/i915/hdcp: Add encoder check in
      intel_hdcp_get_capability (bsc#1233547).
    * CVE-2024-53055: wifi: iwlwifi: mvm: fix 6 GHz scan construction
      (bsc#1233550).
    * CVE-2024-53056: drm/mediatek: Fix potential NULL dereference in
     ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-rt", rpm:"kernel-devel-rt~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-rt", rpm:"kernel-source-rt~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt", rpm:"ocfs2-kmp-rt~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso", rpm:"kernel-rt_debug-vdso~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt-debuginfo", rpm:"gfs2-kmp-rt-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debuginfo", rpm:"kernel-rt_debug-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch", rpm:"kernel-rt-livepatch~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra", rpm:"kernel-rt-extra~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional", rpm:"kernel-rt-optional~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel", rpm:"kernel-rt_debug-devel~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt", rpm:"cluster-md-kmp-rt~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debugsource", rpm:"kernel-rt-debugsource~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso", rpm:"kernel-rt-vdso~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-rt", rpm:"kernel-syms-rt~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-optional-debuginfo", rpm:"kernel-rt-optional-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-rt", rpm:"gfs2-kmp-rt~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt", rpm:"kselftests-kmp-rt~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt-debuginfo", rpm:"reiserfs-kmp-rt-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-debugsource", rpm:"kernel-rt_debug-debugsource~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-rt", rpm:"reiserfs-kmp-rt~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-devel-debuginfo", rpm:"kernel-rt_debug-devel-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-extra-debuginfo", rpm:"kernel-rt-extra-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt", rpm:"dlm-kmp-rt~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-rt-debuginfo", rpm:"kselftests-kmp-rt-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-rt-debuginfo", rpm:"ocfs2-kmp-rt-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-livepatch-devel", rpm:"kernel-rt-livepatch-devel~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-rt-debuginfo", rpm:"dlm-kmp-rt-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-debuginfo", rpm:"kernel-rt-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel", rpm:"kernel-rt-devel~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-vdso-debuginfo", rpm:"kernel-rt-vdso-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-debuginfo", rpm:"kernel-rt-devel-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug-vdso-debuginfo", rpm:"kernel-rt_debug-vdso-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-rt-debuginfo", rpm:"cluster-md-kmp-rt-debuginfo~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt_debug", rpm:"kernel-rt_debug~5.14.21~150500.13.82.1", rls:"openSUSELeap15.5"))) {
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