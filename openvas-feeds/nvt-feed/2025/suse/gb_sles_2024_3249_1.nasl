# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3249.1");
  script_cve_id("CVE-2021-4441", "CVE-2022-0854", "CVE-2022-20368", "CVE-2022-28748", "CVE-2022-2964", "CVE-2022-48686", "CVE-2022-48775", "CVE-2022-48778", "CVE-2022-48787", "CVE-2022-48788", "CVE-2022-48789", "CVE-2022-48790", "CVE-2022-48791", "CVE-2022-48798", "CVE-2022-48802", "CVE-2022-48805", "CVE-2022-48811", "CVE-2022-48823", "CVE-2022-48824", "CVE-2022-48827", "CVE-2022-48834", "CVE-2022-48835", "CVE-2022-48836", "CVE-2022-48837", "CVE-2022-48838", "CVE-2022-48839", "CVE-2022-48843", "CVE-2022-48851", "CVE-2022-48853", "CVE-2022-48856", "CVE-2022-48857", "CVE-2022-48858", "CVE-2022-48872", "CVE-2022-48873", "CVE-2022-48901", "CVE-2022-48905", "CVE-2022-48912", "CVE-2022-48917", "CVE-2022-48919", "CVE-2022-48925", "CVE-2022-48926", "CVE-2022-48928", "CVE-2022-48930", "CVE-2022-48933", "CVE-2022-48934", "CVE-2023-1582", "CVE-2023-2176", "CVE-2023-52854", "CVE-2024-26583", "CVE-2024-26584", "CVE-2024-26800", "CVE-2024-40910", "CVE-2024-41009", "CVE-2024-41011", "CVE-2024-41062", "CVE-2024-42077", "CVE-2024-42232", "CVE-2024-42271", "CVE-2024-43861", "CVE-2024-43882", "CVE-2024-43883", "CVE-2024-44947");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-19 20:03:31 +0000 (Mon, 19 Aug 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3249-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3249-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243249-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195957");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1202346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220185");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222251");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225584");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227932");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227964");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227969");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227985");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229707");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/036898.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:3249-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2024-44947: Initialize beyond-EOF page contents before setting uptodate (bsc#1229454).
- CVE-2022-48919: Fix double free race when mount fails in cifs_get_root() (bsc#1229657).
- CVE-2023-52854: Fix refcnt handling in padata_free_shell() (bsc#1225584).
- CVE-2024-43883: Do not drop references before new references are gained (bsc#1229707).
- CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).
- CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).
- CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage. (bsc#1229503)
- CVE-2022-48912: Fix use-after-free in __nf_register_net_hook() (bsc#1229641)
- CVE-2022-48872: Fix use-after-free race condition for maps (bsc#1229510).
- CVE-2022-48873: Do not remove map on creater_process and device_release (bsc#1229512).
- CVE-2024-42271: Fixed a use after free in iucv_sock_close(). (bsc#1229400)
- CVE-2024-42232: Fixed a race between delayed_work() and ceph_monc_stop(). (bsc#1228959)
- CVE-2024-40910: Fix refcount imbalance on inbound connections (bsc#1227832).
- CVE-2022-48686: Fixed UAF when detecting digest errors (bsc#1223948).
- CVE-2024-41009: bpf: Fix overrunning reservations in ringbuf (bsc#1228020).
- CVE-2022-48791: Fix use-after-free for aborted TMF sas_task (bsc#1228002)

The following non-security bugs were fixed:

- Bluetooth: L2CAP: Fix deadlock (git-fixes).
- powerpc: Remove support for PowerPC 601 (Remove unused and malformed assembly causing build error).
- sched/psi: use kernfs polling functions for PSI trigger polling (bsc#1209799 bsc#1225109).
- scsi: pm80xx: Fix TMF task completion race condition (bsc#1228002).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150300.59.174.1.150300.18.103.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150300.59.174.1", rls:"SLES15.0SP3"))) {
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
