# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856506");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2021-4441", "CVE-2022-4382", "CVE-2022-48868", "CVE-2022-48869", "CVE-2022-48870", "CVE-2022-48871", "CVE-2022-48872", "CVE-2022-48873", "CVE-2022-48875", "CVE-2022-48878", "CVE-2022-48880", "CVE-2022-48890", "CVE-2022-48891", "CVE-2022-48896", "CVE-2022-48898", "CVE-2022-48899", "CVE-2022-48903", "CVE-2022-48904", "CVE-2022-48905", "CVE-2022-48907", "CVE-2022-48909", "CVE-2022-48912", "CVE-2022-48913", "CVE-2022-48914", "CVE-2022-48915", "CVE-2022-48916", "CVE-2022-48917", "CVE-2022-48918", "CVE-2022-48919", "CVE-2022-48921", "CVE-2022-48924", "CVE-2022-48925", "CVE-2022-48926", "CVE-2022-48927", "CVE-2022-48928", "CVE-2022-48929", "CVE-2022-48930", "CVE-2022-48931", "CVE-2022-48932", "CVE-2022-48934", "CVE-2022-48935", "CVE-2022-48937", "CVE-2022-48938", "CVE-2022-48941", "CVE-2022-48942", "CVE-2022-48943", "CVE-2023-52489", "CVE-2023-52893", "CVE-2023-52894", "CVE-2023-52896", "CVE-2023-52898", "CVE-2023-52900", "CVE-2023-52901", "CVE-2023-52905", "CVE-2023-52907", "CVE-2023-52911", "CVE-2024-40910", "CVE-2024-41009", "CVE-2024-41011", "CVE-2024-41062", "CVE-2024-41087", "CVE-2024-42077", "CVE-2024-42126", "CVE-2024-42230", "CVE-2024-42232", "CVE-2024-42271", "CVE-2024-43853", "CVE-2024-43861", "CVE-2024-43882", "CVE-2024-43883", "CVE-2024-44938", "CVE-2024-44947", "CVE-2024-45003");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-19 20:03:31 +0000 (Mon, 19 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-26 04:00:34 +0000 (Thu, 26 Sep 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:3408-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3408-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TGC7PQ5QNGEZWYIHCKH2KPZMGYJ4VN6B");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:3408-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).

  * CVE-2024-44947: Initialize beyond-EOF page contents before setting up-to-date
      (bsc#1229454).

  * CVE-2024-43883: Do not drop references before new references are gained
      (bsc#1229707).

  * CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).

  * CVE-2023-52489: Fix race in accessing memory_section->usage (bsc#1221326).

  * CVE-2024-44938: Fix shift-out-of-bounds in dbDiscardAG (bsc#1229792).

  * CVE-2024-41087: Fix double free on error (CVE-2024-41087,bsc#1228466).

  * CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage.
      (bsc#1229503)

  * CVE-2022-48935: Fixed an unregister flowtable hooks on netns exit
      (bsc#1229619)

  * CVE-2022-48912: Fix use-after-free in __nf_register_net_hook() (bsc#1229641)

  * CVE-2024-42271: Fixed a use after free in iucv_sock_close(). (bsc#1229400)

  * CVE-2024-42232: Fixed a race between delayed_work() and ceph_monc_stop().
      (bsc#1228959)

  * CVE-2024-40910: Fix refcount imbalance on inbound connections (bsc#1227832).

  * CVE-2024-41009: Fix overrunning reservations in ringbuf (bsc#1228020).

  * CVE-2024-45003: Don't evict inode under the inode lru traversing context
      (bsc#1230245).

  The following non-security bugs were fixed:

  * Bluetooth: L2CAP: Fix deadlock (git-fixes).

  * mm, kmsan: fix infinite recursion due to RCU critical section (git-fixes).

  * mm: prevent dereferencing NULL ptr in pfn_section_valid() (git-fixes).

  * Revert 'mm: prevent dereferencing NULL ptr in pfn_section_valid()'
      (bsc#1230413).

  * Revert 'mm, kmsan: fix infinite recursion due to RCU critical section'
      (bsc#1230413).

  * Revert 'mm/sparsemem: fix race in accessing memory_section->usage'
      (bsc#1230413).

  * nvme_core: scan namespaces asynchronously (bsc#1224105).

   Special Instructions and Notes:

  * Please reboot the system after installing this update.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-livepatch-devel", rpm:"kernel-debug-livepatch-devel~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.133.2.150400.24.64.5", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-livepatch-devel", rpm:"kernel-kvmsmall-livepatch-devel~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debugsource", rpm:"kernel-kvmsmall-debugsource~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-debuginfo", rpm:"kernel-kvmsmall-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~5.14.21~150400.24.133.2.150400.24.64.5", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel-debuginfo", rpm:"kernel-kvmsmall-devel-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional", rpm:"kernel-default-optional~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default-debuginfo", rpm:"kselftests-kmp-default-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default-debuginfo", rpm:"ocfs2-kmp-default-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional-debuginfo", rpm:"kernel-default-optional-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra-debuginfo", rpm:"kernel-default-extra-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default-debuginfo", rpm:"cluster-md-kmp-default-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default-debuginfo", rpm:"dlm-kmp-default-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default-debuginfo", rpm:"gfs2-kmp-default-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch-devel", rpm:"kernel-default-livepatch-devel~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_133-default-debuginfo-1", rpm:"kernel-livepatch-5_14_21-150400_24_133-default-debuginfo-1~150400.9.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-5_14_21-150400_24_133-default-1", rpm:"kernel-livepatch-5_14_21-150400_24_133-default-1~150400.9.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-livepatch-SLE15-SP4_Update_31-debugsource-1", rpm:"kernel-livepatch-SLE15-SP4_Update_31-debugsource-1~150400.9.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-aarch64", rpm:"dtb-aarch64~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amd", rpm:"dtb-amd~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-freescale", rpm:"dtb-freescale~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-renesas", rpm:"dtb-renesas~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-nvidia", rpm:"dtb-nvidia~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-xilinx", rpm:"dtb-xilinx~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-allwinner", rpm:"dtb-allwinner~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb-debuginfo", rpm:"gfs2-kmp-64kb-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional", rpm:"kernel-64kb-optional~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb", rpm:"kselftests-kmp-64kb~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb-debuginfo", rpm:"dlm-kmp-64kb-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-altera", rpm:"dtb-altera~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb", rpm:"cluster-md-kmp-64kb~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb-debuginfo", rpm:"cluster-md-kmp-64kb-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-lg", rpm:"dtb-lg~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-exynos", rpm:"dtb-exynos~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-marvell", rpm:"dtb-marvell~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb", rpm:"ocfs2-kmp-64kb~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional-debuginfo", rpm:"kernel-64kb-optional-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb", rpm:"reiserfs-kmp-64kb~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-socionext", rpm:"dtb-socionext~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-cavium", rpm:"dtb-cavium~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra-debuginfo", rpm:"kernel-64kb-extra-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-sprd", rpm:"dtb-sprd~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amlogic", rpm:"dtb-amlogic~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-mediatek", rpm:"dtb-mediatek~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-hisilicon", rpm:"dtb-hisilicon~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb", rpm:"gfs2-kmp-64kb~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-qcom", rpm:"dtb-qcom~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb-debuginfo", rpm:"reiserfs-kmp-64kb-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb", rpm:"dlm-kmp-64kb~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apple", rpm:"dtb-apple~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb-debuginfo", rpm:"ocfs2-kmp-64kb-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apm", rpm:"dtb-apm~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amazon", rpm:"dtb-amazon~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-livepatch-devel", rpm:"kernel-64kb-livepatch-devel~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb-debuginfo", rpm:"kselftests-kmp-64kb-debuginfo~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-broadcom", rpm:"dtb-broadcom~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-rockchip", rpm:"dtb-rockchip~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-arm", rpm:"dtb-arm~5.14.21~150400.24.133.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.133.2", rls:"openSUSELeap15.4"))) {
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
