# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2183.1");
  script_cve_id("CVE-2021-3743", "CVE-2021-39698", "CVE-2021-43056", "CVE-2021-43527", "CVE-2021-47104", "CVE-2021-47220", "CVE-2021-47229", "CVE-2021-47231", "CVE-2021-47236", "CVE-2021-47239", "CVE-2021-47240", "CVE-2021-47246", "CVE-2021-47252", "CVE-2021-47254", "CVE-2021-47255", "CVE-2021-47259", "CVE-2021-47260", "CVE-2021-47261", "CVE-2021-47267", "CVE-2021-47269", "CVE-2021-47270", "CVE-2021-47274", "CVE-2021-47275", "CVE-2021-47276", "CVE-2021-47280", "CVE-2021-47284", "CVE-2021-47285", "CVE-2021-47288", "CVE-2021-47289", "CVE-2021-47296", "CVE-2021-47301", "CVE-2021-47302", "CVE-2021-47305", "CVE-2021-47307", "CVE-2021-47308", "CVE-2021-47314", "CVE-2021-47315", "CVE-2021-47320", "CVE-2021-47321", "CVE-2021-47323", "CVE-2021-47324", "CVE-2021-47330", "CVE-2021-47332", "CVE-2021-47333", "CVE-2021-47334", "CVE-2021-47338", "CVE-2021-47341", "CVE-2021-47344", "CVE-2021-47347", "CVE-2021-47350", "CVE-2021-47354", "CVE-2021-47356", "CVE-2021-47369", "CVE-2021-47375", "CVE-2021-47378", "CVE-2021-47381", "CVE-2021-47382", "CVE-2021-47383", "CVE-2021-47388", "CVE-2021-47391", "CVE-2021-47393", "CVE-2021-47395", "CVE-2021-47396", "CVE-2021-47399", "CVE-2021-47402", "CVE-2021-47404", "CVE-2021-47405", "CVE-2021-47416", "CVE-2021-47423", "CVE-2021-47424", "CVE-2021-47425", "CVE-2021-47431", "CVE-2021-47434", "CVE-2021-47436", "CVE-2021-47441", "CVE-2021-47442", "CVE-2021-47443", "CVE-2021-47445", "CVE-2021-47456", "CVE-2021-47460", "CVE-2021-47464", "CVE-2021-47465", "CVE-2021-47468", "CVE-2021-47473", "CVE-2021-47482", "CVE-2021-47483", "CVE-2021-47485", "CVE-2021-47495", "CVE-2021-47496", "CVE-2021-47497", "CVE-2021-47500", "CVE-2021-47505", "CVE-2021-47506", "CVE-2021-47511", "CVE-2021-47516", "CVE-2021-47522", "CVE-2021-47538", "CVE-2021-47541", "CVE-2021-47542", "CVE-2021-47562", "CVE-2021-47563", "CVE-2021-47565", "CVE-2022-20132", "CVE-2022-48673", "CVE-2023-0160", "CVE-2023-1829", "CVE-2023-2176", "CVE-2023-4244", "CVE-2023-47233", "CVE-2023-52433", "CVE-2023-52581", "CVE-2023-52591", "CVE-2023-52654", "CVE-2023-52655", "CVE-2023-52686", "CVE-2023-52840", "CVE-2023-52871", "CVE-2023-52880", "CVE-2023-6531", "CVE-2024-26581", "CVE-2024-26643", "CVE-2024-26828", "CVE-2024-26925", "CVE-2024-26929", "CVE-2024-26930", "CVE-2024-27398", "CVE-2024-27413", "CVE-2024-35811", "CVE-2024-35895", "CVE-2024-35914");
  script_tag(name:"creation_date", value:"2025-02-17 04:07:12 +0000 (Mon, 17 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 14:32:02 +0000 (Thu, 16 Dec 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2183-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2183-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242183-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1151927");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1154353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1184631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185589");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1185902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1188772");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1189883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191452");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210335");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217169");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220137");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221829");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223934");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224099");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224438");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224482");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224846");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224892");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224909");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224917");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224923");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224953");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224961");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224963");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224965");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224990");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225238");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225262");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225301");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225318");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225321");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225327");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225328");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225366");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225393");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225411");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225448");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225534");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035717.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:2183-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2021-47497: Fixed shift-out-of-bound (UBSAN) with byte size cells (bsc#1225355).
- CVE-2021-47500: Fixed trigger reference couting (bsc#1225360).
- CVE-2021-47383: Fiedx out-of-bound vmalloc access in imageblit (bsc#1225208).
- CVE-2021-47511: Fixed negative period/buffer sizes (bsc#1225411).
- CVE-2024-27398: Fixed use-after-free bugs caused by sco_sock_timeout (bsc#1224174).
- CVE-2023-4244: Fixed a use-after-free in the nf_tables component, which could be exploited to achieve local privilege escalation (bsc#1215420).
- CVE-2023-4244: Fixed a use-after-free in the nf_tables component, which could be exploited to achieve local privilege escalation (bsc#1215420).
- CVE-2023-1829: Fixed a use-after-free vulnerability in the control index filter (tcindex) (bsc#1210335).
- CVE-2021-47378: Destroy cm id before destroy qp to avoid use after free (bsc#1225201).
- CVE-2021-47496: Fix flipped sign in tls_err_abort() calls (bsc#1225354)
- CVE-2021-47402: Protect fl_walk() with rcu (bsc#1225301)
- CVE-2022-48673: kABI workarounds for struct smc_link (bsc#1223934).
- CVE-2023-52871: Handle a second device without data corruption (bsc#1225534)
- CVE-2024-26828: Fix underflow in parse_server_interfaces() (bsc#1223084).
- CVE-2024-27413: Fix incorrect allocation size (bsc#1224438).
- CVE-2023-52840: Fix use after free in rmi_unregister_function() (bsc#1224928).
- CVE-2021-47261: Fix initializing CQ fragments buffer (bsc#1224954)
- CVE-2021-47254: Fix use-after-free in gfs2_glock_shrink_scan (bsc#1224888).
- CVE-2023-52655: Check packet for fixup for true limit (bsc#1217169).
- CVE-2023-52686: Fix a null pointer in opal_event_init() (bsc#1065729).

The following non-security bugs were fixed:

- NFC: nxp: add NXP1002 (bsc#1185589).
- PCI: rpaphp: Add MODULE_DESCRIPTION (bsc#1176869 ltc#188243).
- af_unix: Do not use atomic ops for unix_sk(sk)->inflight (bsc#1223384).
- af_unix: Replace BUG_ON() with WARN_ON_ONCE() (bsc#1223384).
- af_unix: annote lockless accesses to unix_tot_inflight & gc_in_progress (bsc#1223384).
- btrfs: do not start relocation until in progress drops are done (bsc#1222251).
- md: Replace snprintf with scnprintf (git-fixes).
- netfilter: nf_tables: GC transaction race with abort path (git-fixes).
- netfilter: nf_tables: GC transaction race with netns dismantle (git-fixes).
- netfilter: nf_tables: defer gc run if previous batch is still pending (git-fixes).
- netfilter: nf_tables: fix GC transaction races with netns and netlink event exit path (git-fixes).
- netfilter: nf_tables: fix kdoc warnings after gc rework (git-fixes).
- netfilter: nf_tables: fix memleak when more than 255 elements expired (git-fixes).
- netfilter: nf_tables: mark newset as dead on transaction abort (git-fixes).
- netfilter: nf_tables: mark set as dead when ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.194.1.150200.9.99.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.194.1", rls:"SLES15.0SP2"))) {
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
