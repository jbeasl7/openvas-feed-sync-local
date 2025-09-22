# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2623.1");
  script_cve_id("CVE-2020-10135", "CVE-2020-14314", "CVE-2020-14331", "CVE-2020-14356", "CVE-2020-14386", "CVE-2020-16166", "CVE-2020-1749", "CVE-2020-24394");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-22 18:24:17 +0000 (Tue, 22 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2623-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2623-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202623-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1058115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1071995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1144333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1165629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175691");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176069");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-September/007419.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2623-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2020-1749: Use ip6_dst_lookup_flow instead of ip6_dst_lookup (bsc#1165629).
- CVE-2020-14314: Fixed a potential negative array index in do_split() (bsc#1173798).
- CVE-2020-14356: Fixed a null pointer dereference in cgroupv2 subsystem which could have led to privilege escalation (bsc#1175213).
- CVE-2020-14331: Fixed a missing check in vgacon scrollback handling (bsc#1174205).
- CVE-2020-16166: Fixed a potential issue which could have allowed remote attackers to make observations that help to obtain sensitive information about the internal state of the network RNG (bsc#1174757).
- CVE-2020-24394: Fixed an issue which could set incorrect permissions on new filesystem objects when the filesystem lacks ACL support (bsc#1175518).
- CVE-2020-10135: Legacy pairing and secure-connections pairing authentication Bluetooth might have allowed an unauthenticated user to complete authentication without pairing credentials via adjacent access (bsc#1171988).
- CVE-2020-14386: Fixed a potential local privilege escalation via memory corruption (bsc#1176069).

The following non-security bugs were fixed:

- btrfs: remove a BUG_ON() from merge_reloc_roots() (bsc#1174784).
- cifs: document and cleanup dfs mount (bsc#1144333 bsc#1172428).
- cifs: Fix an error pointer dereference in cifs_mount() (bsc#1144333 bsc#1172428).
- cifs: fix double free error on share and prefix (bsc#1144333 bsc#1172428).
- cifs: handle empty list of targets in cifs_reconnect() (bsc#1144333 bsc#1172428).
- cifs: handle RESP_GET_DFS_REFERRAL.PathConsumed in reconnect (bsc#1144333 bsc#1172428).
- cifs: merge __{cifs,smb2}_reconnect[_tcon]() into cifs_tree_connect() (bsc#1144333 bsc#1172428).
- cifs: only update prefix path of DFS links in cifs_tree_connect() (bsc#1144333 bsc#1172428).
- cifs: reduce number of referral requests in DFS link lookups (bsc#1144333 bsc#1172428).
- cifs: rename reconn_inval_dfs_target() (bsc#1144333 bsc#1172428).
- Drivers: hv: vmbus: Only notify Hyper-V for die events that are oops (bsc#1175127).
- ibmvnic: Fix IRQ mapping disposal in error path (bsc#1175112 ltc#187459).
- ip6_tunnel: allow not to count pkts on tstats by passing dev as NULL (bsc#1175515).
- ip_tunnel: allow not to count pkts on tstats by setting skb's dev to NULL (bsc#1175515).
- ipvs: fix the connection sync failed in some cases (bsc#1174699).
- kabi: hide new parameter of ip6_dst_lookup_flow() (bsc#1165629).
- kabi: mask changes to struct ipv6_stub (bsc#1165629).
- mm: Avoid calling build_all_zonelists_init under hotplug context (bsc#1154366).
- mm, vmstat: reduce zone->lock holding time by /proc/pagetypeinfo (bsc#1175691).
- ocfs2: add trimfs dlm lock resource (bsc#1175228).
- ocfs2: add trimfs lock to avoid duplicated trims in cluster (bsc#1175228).
- ocfs2: avoid inode removal ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.60.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.60.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.60.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.60.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.60.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.60.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.60.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.60.1", rls:"SLES12.0SP4"))) {
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
