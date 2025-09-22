# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3408.1");
  script_cve_id("CVE-2021-4441", "CVE-2022-4382", "CVE-2022-48868", "CVE-2022-48869", "CVE-2022-48870", "CVE-2022-48871", "CVE-2022-48872", "CVE-2022-48873", "CVE-2022-48875", "CVE-2022-48878", "CVE-2022-48880", "CVE-2022-48890", "CVE-2022-48891", "CVE-2022-48896", "CVE-2022-48898", "CVE-2022-48899", "CVE-2022-48903", "CVE-2022-48904", "CVE-2022-48905", "CVE-2022-48907", "CVE-2022-48909", "CVE-2022-48912", "CVE-2022-48913", "CVE-2022-48914", "CVE-2022-48915", "CVE-2022-48916", "CVE-2022-48917", "CVE-2022-48918", "CVE-2022-48919", "CVE-2022-48921", "CVE-2022-48924", "CVE-2022-48925", "CVE-2022-48926", "CVE-2022-48927", "CVE-2022-48928", "CVE-2022-48929", "CVE-2022-48930", "CVE-2022-48931", "CVE-2022-48932", "CVE-2022-48934", "CVE-2022-48935", "CVE-2022-48937", "CVE-2022-48938", "CVE-2022-48941", "CVE-2022-48942", "CVE-2022-48943", "CVE-2023-52489", "CVE-2023-52893", "CVE-2023-52894", "CVE-2023-52896", "CVE-2023-52898", "CVE-2023-52900", "CVE-2023-52901", "CVE-2023-52905", "CVE-2023-52907", "CVE-2023-52911", "CVE-2024-40910", "CVE-2024-41009", "CVE-2024-41011", "CVE-2024-41062", "CVE-2024-41087", "CVE-2024-42077", "CVE-2024-42126", "CVE-2024-42230", "CVE-2024-42232", "CVE-2024-42271", "CVE-2024-43853", "CVE-2024-43861", "CVE-2024-43882", "CVE-2024-43883", "CVE-2024-44938", "CVE-2024-44947", "CVE-2024-45003");
  script_tag(name:"creation_date", value:"2025-02-13 14:53:48 +0000 (Thu, 13 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-19 20:03:31 +0000 (Mon, 19 Aug 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3408-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3408-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243408-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207158");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221326");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228020");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228959");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229400");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229454");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229503");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229506");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229508");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229510");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229516");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229522");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229528");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229531");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229544");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229565");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229566");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229581");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229598");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229603");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229604");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229612");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229613");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229622");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229624");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229625");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229626");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229630");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229631");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229635");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229638");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229657");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229707");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229792");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230413");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-September/037033.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:3408-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.

The following security bugs were fixed:

- CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).
- CVE-2024-44947: Initialize beyond-EOF page contents before setting uptodate (bsc#1229454).
- CVE-2024-43883: Do not drop references before new references are gained (bsc#1229707).
- CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).
- CVE-2023-52489: Fix race in accessing memory_section->usage (bsc#1221326).
- CVE-2024-44938: Fix shift-out-of-bounds in dbDiscardAG (bsc#1229792).
- CVE-2024-41087: Fix double free on error (CVE-2024-41087,bsc#1228466).
- CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage. (bsc#1229503)
- CVE-2022-48935: Fixed an unregister flowtable hooks on netns exit (bsc#1229619)
- CVE-2022-48912: Fix use-after-free in __nf_register_net_hook() (bsc#1229641)
- CVE-2024-42271: Fixed a use after free in iucv_sock_close(). (bsc#1229400)
- CVE-2024-42232: Fixed a race between delayed_work() and ceph_monc_stop(). (bsc#1228959)
- CVE-2024-40910: Fix refcount imbalance on inbound connections (bsc#1227832).
- CVE-2024-41009: Fix overrunning reservations in ringbuf (bsc#1228020).
- CVE-2024-45003: Don't evict inode under the inode lru traversing context (bsc#1230245).

The following non-security bugs were fixed:

- Bluetooth: L2CAP: Fix deadlock (git-fixes).
- mm, kmsan: fix infinite recursion due to RCU critical section (git-fixes).
- mm: prevent derefencing NULL ptr in pfn_section_valid() (git-fixes).
- Revert 'mm: prevent derefencing NULL ptr in pfn_section_valid()' (bsc#1230413).
- Revert 'mm, kmsan: fix infinite recursion due to RCU critical section' (bsc#1230413).
- Revert 'mm/sparsemem: fix race in accessing memory_section->usage' (bsc#1230413).
- nvme_core: scan namespaces asynchronously (bsc#1224105).");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.133.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.133.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.133.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.133.2.150400.24.64.5", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.133.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.133.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.133.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.133.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.133.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.133.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.133.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.133.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.133.2", rls:"SLES15.0SP4"))) {
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
