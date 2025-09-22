# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02308.1");
  script_cve_id("CVE-2022-1679", "CVE-2022-2586", "CVE-2022-2905", "CVE-2022-3903", "CVE-2022-4095", "CVE-2022-4662", "CVE-2022-49934", "CVE-2022-49936", "CVE-2022-49937", "CVE-2022-49942", "CVE-2022-49945", "CVE-2022-49948", "CVE-2022-49950", "CVE-2022-49952", "CVE-2022-49954", "CVE-2022-49956", "CVE-2022-49968", "CVE-2022-49977", "CVE-2022-49978", "CVE-2022-49981", "CVE-2022-49984", "CVE-2022-49985", "CVE-2022-49986", "CVE-2022-49987", "CVE-2022-49989", "CVE-2022-49990", "CVE-2022-49993", "CVE-2022-50010", "CVE-2022-50012", "CVE-2022-50019", "CVE-2022-50020", "CVE-2022-50022", "CVE-2022-50027", "CVE-2022-50028", "CVE-2022-50029", "CVE-2022-50030", "CVE-2022-50032", "CVE-2022-50033", "CVE-2022-50036", "CVE-2022-50038", "CVE-2022-50045", "CVE-2022-50051", "CVE-2022-50059", "CVE-2022-50061", "CVE-2022-50065", "CVE-2022-50067", "CVE-2022-50072", "CVE-2022-50083", "CVE-2022-50084", "CVE-2022-50085", "CVE-2022-50087", "CVE-2022-50091", "CVE-2022-50092", "CVE-2022-50093", "CVE-2022-50094", "CVE-2022-50097", "CVE-2022-50098", "CVE-2022-50099", "CVE-2022-50101", "CVE-2022-50102", "CVE-2022-50104", "CVE-2022-50108", "CVE-2022-50109", "CVE-2022-50118", "CVE-2022-50124", "CVE-2022-50126", "CVE-2022-50127", "CVE-2022-50136", "CVE-2022-50138", "CVE-2022-50140", "CVE-2022-50141", "CVE-2022-50142", "CVE-2022-50143", "CVE-2022-50146", "CVE-2022-50149", "CVE-2022-50152", "CVE-2022-50153", "CVE-2022-50156", "CVE-2022-50158", "CVE-2022-50160", "CVE-2022-50161", "CVE-2022-50162", "CVE-2022-50164", "CVE-2022-50165", "CVE-2022-50169", "CVE-2022-50172", "CVE-2022-50173", "CVE-2022-50176", "CVE-2022-50179", "CVE-2022-50181", "CVE-2022-50185", "CVE-2022-50191", "CVE-2022-50200", "CVE-2022-50209", "CVE-2022-50211", "CVE-2022-50212", "CVE-2022-50213", "CVE-2022-50215", "CVE-2022-50218", "CVE-2022-50220", "CVE-2022-50222", "CVE-2022-50229", "CVE-2022-50231", "CVE-2023-3111", "CVE-2024-26924", "CVE-2024-27397", "CVE-2024-36978", "CVE-2024-46800", "CVE-2024-53141", "CVE-2024-56770", "CVE-2025-21700", "CVE-2025-21702", "CVE-2025-21703", "CVE-2025-37752", "CVE-2025-37798", "CVE-2025-37823", "CVE-2025-37890", "CVE-2025-37932", "CVE-2025-37953", "CVE-2025-37997", "CVE-2025-38000", "CVE-2025-38001", "CVE-2025-38083");
  script_tag(name:"creation_date", value:"2025-07-16 04:19:33 +0000 (Wed, 16 Jul 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-10 19:25:08 +0000 (Tue, 10 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02308-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02308-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502308-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1201956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202810");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1205514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211226");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224095");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225820");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230827");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234381");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1235637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237159");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238471");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1238570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240785");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242414");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243330");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243543");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244234");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244241");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244771");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244773");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244774");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244782");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244783");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244786");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244793");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244797");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244813");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244825");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244839");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244841");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244842");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244845");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244851");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244856");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244868");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244881");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244884");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244908");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244984");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245033");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245098");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245103");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245117");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245122");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245138");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245139");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245146");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245195");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245265");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245455");
  script_xref(name:"URL", value:"https://github.com/openSUSE/rpm-config-SUSE/pull/82");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-July/040707.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:02308-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2022-50085: dm raid: fix address sanitizer warning in raid_resume (bsc#1245147).
- CVE-2022-50087: firmware: arm_scpi: Ensure scpi_info is not assigned if the probe fails (bsc#1245119).
- CVE-2022-50200: selinux: Add boundary check in put_entry() (bsc#1245149).
- CVE-2024-26924: scsi: lpfc: Release hbalock before calling lpfc_worker_wake_up() (bsc#1225820).
- CVE-2024-27397: kabi: place tstamp needed for nftables set in a hole (bsc#1224095).
- CVE-2024-36978: net: sched: sch_multiq: fix possible OOB write in multiq_tune() (bsc#1226514).
- CVE-2024-46800: sch/netem: fix use after free in netem_dequeue (bsc#1230827).
- CVE-2024-53141: netfilter: ipset: add missing range check in bitmap_ip_uadt (bsc#1234381).
- CVE-2024-56770: sch/netem: fix use after free in netem_dequeue (bsc#1235637).
- CVE-2025-21700: net: sched: Disallow replacing of child qdisc from one parent to another (bsc#1237159).
- CVE-2025-21702: pfifo_tail_enqueue: Drop new packet when sch->limit == 0 (bsc#1237312).
- CVE-2025-21703: netem: Update sch->q.qlen before qdisc_tree_reduce_backlog() (bsc#1237313).
- CVE-2025-37752: net_sched: sch_sfq: move the limit validation (bsc#1242504).
- CVE-2025-37823: net_sched: hfsc: Fix a potential UAF in hfsc_dequeue() too (bsc#1242924).
- CVE-2025-37890: net_sched: hfsc: Fix a UAF vulnerability in class with netem as child qdisc (bsc#1243330).
- CVE-2025-37997: netfilter: ipset: fix region locking in hash types (bsc#1243832).
- CVE-2025-38000: sch_hfsc: Fix qlen accounting bug when using peek in hfsc_enqueue() (bsc#1244277).
- CVE-2025-38001: net_sched: hfsc: Address reentrant enqueue adding class to eltree twice (bsc#1244234).
- CVE-2025-38083: net_sched: prio: fix a race in prio_tune() (bsc#1245183).

The following non-security bugs were fixed:

- Fix conditional for selecting gcc-13 Fixes: 51dacec21eb1 ('Use gcc-13 for build on SLE16 (jsc#PED-10028).')
- MyBS: Correctly generate build flags for non-multibuild package limit (bsc# 1244241) Fixes: 0999112774fc ('MyBS: Use buildflags to set which package to build')
- MyBS: Do not build kernel-obs-qa with limit_packages Fixes: 58e3f8c34b2b ('bs-upload-kernel: Pass limit_packages also on multibuild')
- MyBS: Simplify qa_expr generation Start with a 0 which makes the expression valid even if there are no QA repositories (currently does not happen). Then separator is always needed.
- Require zstd in kernel-default-devel when module compression is zstd To use ksym-provides tool modules need to be uncompressed. Without zstd at least kernel-default-base does not have provides. Link: [link moved to references]
- Test the correct macro to detect RT kernel build Fixes: 470cd1a41502 ('kernel-binary: Support livepatch_rt with merged RT branch')
- Use gcc-13 for build on SLE16 (jsc#PED-10028).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.211.1.150300.18.126.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.212.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.211.1", rls:"SLES15.0SP3"))) {
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
