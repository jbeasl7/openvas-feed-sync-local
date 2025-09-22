# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0634.1");
  script_cve_id("CVE-2017-5754", "CVE-2021-4203", "CVE-2022-2991", "CVE-2022-36280", "CVE-2022-4662", "CVE-2022-47929", "CVE-2023-0045", "CVE-2023-0266", "CVE-2023-0590");
  script_tag(name:"creation_date", value:"2025-02-17 04:07:12 +0000 (Mon, 17 Feb 2025)");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-05 15:54:54 +0000 (Fri, 05 May 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0634-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0634-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230634-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1068032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1186449");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201420");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205397");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206640");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206784");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206855");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206873");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206882");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207102");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207795");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207875");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208541");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208570");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-March/013982.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:0634-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2021-4203: Fixed use-after-free read flaw that was found in sock_getsockopt() in net/core/sock.c due to SO_PEERCRED and SO_PEERGROUPS race with listen() (bsc#1194535).
- CVE-2017-5754: Fixed speculative side channel attacks on various CPU platforms (bsc#1068032).
- CVE-2022-36280: Fixed out-of-bounds memory access vulnerability found in vmwgfx driver (bsc#1203332).
- CVE-2023-0045: Fixed missing Flush IBP in ib_prctl_set (bsc#1207773).
- CVE-2022-4662: Fixed incorrect access control in the USB core subsystem that could lead a local user to crash the system (bsc#1206664).
- CVE-2023-0590: Fixed race condition in qdisc_graft() (bsc#1207795).
- CVE-2022-2991: Fixed an heap-based overflow in the lightnvm implemenation (bsc#1201420).
- CVE-2023-0266: Fixed a use-after-free vulnerability inside the ALSA PCM package. SNDRV_CTL_IOCTL_ELEM_{READ<pipe>WRITE}32 was missing locks that could have been used in a use-after-free that could have resulted in a priviledge escalation to gain ring0 access from the system user (bsc#1207134).
- CVE-2022-47929: Fixed NULL pointer dereference bug in the traffic control subsystem (bsc#1207237).

The following non-security bugs were fixed:

- add 00f3ca2c2d66 ('mm: memcontrol: per-lruvec stats infrastructure')
- add 0b3d6e6f2dd0 mm: writeback: use exact memcg dirty counts
- add 168e06f7937d kernel/hung_task.c: force console verbose before panic
- add 1f4aace60b0e ('fs/seq_file.c: simplify seq_file iteration code and interface')
- add 304ae42739b1 kernel/hung_task.c: break RCU locks based on jiffies
- add 401c636a0eeb kernel/hung_task.c: show all hung tasks before panic
- add Tegra repository to git_sort.
- add a1c6ca3c6de7 kernel: hung_task.c: disable on suspend
- add c3cc39118c36 mm: memcontrol: fix NR_WRITEBACK leak in memcg and system stats
- add c892fd82cc06 mm: memcg: add __GFP_NOWARN in __memcg_schedule_kmem_cache_create()
- add e27be240df53 mm: memcg: make sure memory.events is uptodate when waking pollers
- add support for enabling livepatching related packages on -RT (jsc#PED-1706)
- add suse-kernel-rpm-scriptlets to kmp buildreqs (boo#1205149)
- amiflop: clean up on errors during setup (git-fixes).
- audit: ensure userspace is penalized the same as the kernel when under pressure (bsc#1204514).
- audit: improve robustness of the audit queue handling (bsc#1204514).
- bcache: fix super block seq numbers comparision in register_cache_set() (git-fixes).
- blk-cgroup: Fix memleak on error path (git-fixes).
- blk-cgroup: Pre-allocate tree node on blkg_conf_prep (git-fixes).
- blk-cgroup: fix missing put device in error path from blkg_conf_pref() (git-fixes).
- blk-mq: fix possible memleak when register 'hctx' failed (git-fixes).
- blk-mq: insert request not through ->queue_rq into sw/scheduler queue ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.150.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.150.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.150.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.150.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.150.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.150.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.150.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.150.1", rls:"SLES12.0SP5"))) {
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
