# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0984.1");
  script_cve_id("CVE-2025-21738", "CVE-2025-40242", "CVE-2025-71066", "CVE-2026-23004", "CVE-2026-23054", "CVE-2026-23060", "CVE-2026-23191", "CVE-2026-23204", "CVE-2026-23209", "CVE-2026-23268", "CVE-2026-23269");
  script_tag(name:"creation_date", value:"2026-03-26 04:49:18 +0000 (Thu, 26 Mar 2026)");
  script_version("2026-03-26T06:06:30+0000");
  script_tag(name:"last_modification", value:"2026-03-26 06:06:30 +0000 (Thu, 26 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-18 20:46:07 +0000 (Wed, 18 Mar 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0984-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260984-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255075");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259857");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024841.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2026:0984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2025-21738: ata: libata-sff: Ensure that we cannot write outside the allocated buffer (bsc#1238917).
- CVE-2025-40242: gfs2: Fix unlikely race in gdlm_put_lock (bsc#1255075).
- CVE-2025-71066: net/sched: ets: Always remove class from active list before deleting in ets_qdisc_change (bsc#1256645).
- CVE-2026-23004: dst: fix races in rt6_uncached_list_del() and rt_del_uncached_list() (bsc#1257231).
- CVE-2026-23060: crypto: authencesn - reject too-short AAD (assoclen<8) to match ESP/ESN spec (bsc#1257735).
- CVE-2026-23191: ALSA: aloop: Fix racy access at PCM trigger (bsc#1258395).
- CVE-2026-23204: net/sched: cls_u32: use skb_header_pointer_careful() (bsc#1258340).
- CVE-2026-23209: macvlan: fix error recovery in macvlan_common_newlink() (bsc#1258518).
- CVE-2026-23268: apparmor: fix unprivileged local user can do privileged policy management (bsc#1258850).
- CVE-2026-23269: apparmor: validate DFA start states are in bounds in unpack_pdb (bsc#1259857).

The following non-security bugs were fixed:

- Disable CONFIG_NET_SCH_ATM (jsc#PED-12836).
- apparmor: Fix double free of ns_name in aa_replace_profiles() (bsc#1258849).
- apparmor: fix differential encoding verification (bsc#1258849).
- apparmor: fix memory leak in verify_header (bsc#1258849).
- apparmor: fix missing bounds check on DEFAULT table in verify_dfa() (bsc#1258849).
- apparmor: fix race between freeing data and fs accessing it (bsc#1258849).
- apparmor: fix race on rawdata dereference (bsc#1258849).
- apparmor: fix side-effect bug in match_char() macro usage (bsc#1258849).
- apparmor: fix unprivileged local user can do privileged policy management (bsc#1258849).
- apparmor: fix: limit the number of levels of policy namespaces (bsc#1258849).
- apparmor: replace recursive profile removal with iterative approach (bsc#1258849).
- apparmor: validate DFA start states are in bounds in unpack_pdb (bsc#1258849).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.197.1.150400.24.100.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.197.1", rls:"SLES15.0SP4"))) {
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
