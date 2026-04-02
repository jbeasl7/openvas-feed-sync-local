# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.1041.1");
  script_cve_id("CVE-2023-53817", "CVE-2024-38542", "CVE-2025-37861", "CVE-2025-39817", "CVE-2025-39964", "CVE-2025-40099", "CVE-2025-40103", "CVE-2025-40253", "CVE-2025-71066", "CVE-2025-71113", "CVE-2025-71231", "CVE-2026-23004", "CVE-2026-23054", "CVE-2026-23060", "CVE-2026-23074", "CVE-2026-23089", "CVE-2026-23111", "CVE-2026-23141", "CVE-2026-23157", "CVE-2026-23191", "CVE-2026-23202", "CVE-2026-23204", "CVE-2026-23207", "CVE-2026-23209", "CVE-2026-23214", "CVE-2026-23268", "CVE-2026-23269");
  script_tag(name:"creation_date", value:"2026-03-27 04:48:51 +0000 (Fri, 27 Mar 2026)");
  script_version("2026-03-27T06:06:36+0000");
  script_tag(name:"last_modification", value:"2026-03-27 06:06:36 +0000 (Fri, 27 Mar 2026)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-18 20:46:07 +0000 (Wed, 18 Mar 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:1041-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:1041-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20261041-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226591");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245728");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251966");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251971");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252266");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1253049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1255084");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256690");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257231");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257472");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257473");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257790");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258376");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258524");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258849");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1259857");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024928.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2026:1041-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2023-53817: crypto: lib/mpi - avoid null pointer deref in mpi_cmp_ui() (bsc#1254992).
- CVE-2024-38542: RDMA/mana_ib: boundary check before installing cq callbacks (bsc#1226591).
- CVE-2025-37861: scsi: mpi3mr: Synchronous access b/w reset and tm thread for reply queue (bsc#1243055).
- CVE-2025-39817: efivarfs: Fix slab-out-of-bounds in efivarfs_d_compare (bsc#1249998).
- CVE-2025-39964: crypto: af_alg - Disallow concurrent writes in af_alg_sendmsg (bsc#1251966).
- CVE-2025-40099: cifs: parse_dfs_referrals: prevent oob on malformed input (bsc#1252911).
- CVE-2025-40103: smb: client: Fix refcount leak for cifs_sb_tlink (bsc#1252924).
- CVE-2025-40253: s390/ctcm: Fix double-kfree (bsc#1255084).
- CVE-2025-71066: net/sched: ets: Always remove class from active list before deleting in ets_qdisc_change (bsc#1256645).
- CVE-2025-71113: crypto: af_alg - zero initialize memory allocated via sock_kmalloc (bsc#1256716).
- CVE-2025-71231: crypto: iaa - Fix out-of-bounds index in find_empty_iaa_compression_mode (bsc#1258424).
- CVE-2026-23004: dst: fix races in rt6_uncached_list_del() and rt_del_uncached_list() (bsc#1257231).
- CVE-2026-23060: crypto: authencesn - reject too-short AAD (assoclen<8) to match ESP/ESN spec (bsc#1257735).
- CVE-2026-23074: net/sched: Enforce that teql can only be used as root qdisc (bsc#1257749).
- CVE-2026-23089: ALSA: usb-audio: Fix use-after-free in snd_usb_mixer_free() (bsc#1257790).
- CVE-2026-23111: netfilter: nf_tables: fix inverted genmask check in nft_map_catchall_activate() (bsc#1258181).
- CVE-2026-23141: btrfs: send: check for inline extents in range_is_hole_in_parent() (bsc#1258377).
- CVE-2026-23191: ALSA: aloop: Fix racy access at PCM trigger (bsc#1258395).
- CVE-2026-23204: net/sched: cls_u32: use skb_header_pointer_careful() (bsc#1258340).
- CVE-2026-23209: macvlan: fix error recovery in macvlan_common_newlink() (bsc#1258518).
- CVE-2026-23214: btrfs: reject new transactions if the fs is fully read-only (bsc#1258464).
- CVE-2026-23268: apparmor: fix unprivileged local user can do privileged policy management (bsc#1258850).
- CVE-2026-23269: apparmor: validate DFA start states are in bounds in unpack_pdb (bsc#1259857).

The following non-security bugs were fixed:

- Add bugnumber to existing mana change (bsc#1251971).
- Drivers: hv: fix missing kernel-doc description for 'size' in request_arr_init() (git-fixes).
- Drivers: hv: remove stale comment (git-fixes).
- Drivers: hv: vmbus: Clean up sscanf format specifier in target_cpu_store() (git-fixes).
- Drivers: hv: vmbus: Fix sysfs output format for ring buffer index (git-fixes).
- Drivers: hv: vmbus: Fix typos in vmbus_drv.c (git-fixes).
- PCI: hv: Correct a comment (git-fixes).
- PCI: hv: Remove unnecessary flex array in struct pci_packet ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb", rpm:"cluster-md-kmp-64kb~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb", rpm:"dlm-kmp-64kb~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-allwinner", rpm:"dtb-allwinner~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-altera", rpm:"dtb-altera~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amazon", rpm:"dtb-amazon~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amd", rpm:"dtb-amd~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amlogic", rpm:"dtb-amlogic~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apm", rpm:"dtb-apm~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apple", rpm:"dtb-apple~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-arm", rpm:"dtb-arm~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-broadcom", rpm:"dtb-broadcom~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-cavium", rpm:"dtb-cavium~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-exynos", rpm:"dtb-exynos~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-freescale", rpm:"dtb-freescale~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-hisilicon", rpm:"dtb-hisilicon~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-lg", rpm:"dtb-lg~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-marvell", rpm:"dtb-marvell~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-mediatek", rpm:"dtb-mediatek~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-nvidia", rpm:"dtb-nvidia~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-qcom", rpm:"dtb-qcom~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-renesas", rpm:"dtb-renesas~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-rockchip", rpm:"dtb-rockchip~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-socionext", rpm:"dtb-socionext~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-sprd", rpm:"dtb-sprd~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-xilinx", rpm:"dtb-xilinx~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb", rpm:"gfs2-kmp-64kb~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional", rpm:"kernel-64kb-optional~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso", rpm:"kernel-debug-vdso~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~6.4.0~150600.23.92.1.150600.12.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~6.4.0~150600.23.92.1.150600.12.42.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch-devel", rpm:"kernel-default-livepatch-devel~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional", rpm:"kernel-default-optional~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb", rpm:"kselftests-kmp-64kb~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb", rpm:"ocfs2-kmp-64kb~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb", rpm:"reiserfs-kmp-64kb~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~6.4.0~150600.23.92.1", rls:"openSUSELeap15.6"))) {
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
