# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2024.0516.1");
  script_cve_id("CVE-2021-33631", "CVE-2023-46838", "CVE-2023-47233", "CVE-2023-4921", "CVE-2023-51042", "CVE-2023-51043", "CVE-2023-51780", "CVE-2023-51782", "CVE-2023-6040", "CVE-2023-6356", "CVE-2023-6531", "CVE-2023-6535", "CVE-2023-6536", "CVE-2023-6915", "CVE-2024-0340", "CVE-2024-0565", "CVE-2024-0641", "CVE-2024-0775", "CVE-2024-1085", "CVE-2024-1086", "CVE-2024-24860");
  script_tag(name:"creation_date", value:"2025-02-25 14:26:30 +0000 (Tue, 25 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 20:41:24 +0000 (Mon, 05 Feb 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:0516-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0516-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240516-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108281");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1141539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1174649");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194869");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1209834");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1211515");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212091");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215275");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216702");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218447");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218527");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218730");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218804");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218968");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219067");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219412");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219434");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219512");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219582");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219608");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017921.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2024:0516-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-1085: Fixed nf_tables use-after-free vulnerability in the nft_setelem_catchall_deactivate() function (bsc#1219429).
- CVE-2024-1086: Fixed a use-after-free vulnerability inside the nf_tables component that could have been exploited to achieve local privilege escalation (bsc#1219434).
- CVE-2023-51042: Fixed use-after-free in amdgpu_cs_wait_all_fences in drivers/gpu/drm/amd/amdgpu/amdgpu_cs.c (bsc#1219128).
- CVE-2023-51780: Fixed a use-after-free in do_vcc_ioctl in net/atm/ioctl.c, because of a vcc_recvmsg race condition (bsc#1218730).
- CVE-2023-46838: Fixed an issue with Xen netback processing of zero-length transmit fragment (bsc#1218836).
- CVE-2021-33631: Fixed an integer overflow in ext4_write_inline_data_end() (bsc#1219412).
- CVE-2023-6535: Fixed a NULL pointer dereference in nvmet_tcp_execute_request (bsc#1217988).
- CVE-2023-6536: Fixed a NULL pointer dereference in __nvmet_req_complete (bsc#1217989).
- CVE-2023-6356: Fixed a NULL pointer dereference in nvmet_tcp_build_pdu_iovec (bsc#1217987).
- CVE-2023-47233: Fixed a use-after-free in the device unplugging (disconnect the USB by hotplug) code inside the brcm80211 component (bsc#1216702).
- CVE-2023-4921: Fixed a use-after-free vulnerability in the QFQ network scheduler which could be exploited to achieve local privilege escalation (bsc#1215275).
- CVE-2023-51043: Fixed use-after-free during a race condition between a nonblocking atomic commit and a driver unload in drivers/gpu/drm/drm_atomic.c (bsc#1219120).
- CVE-2024-0775: Fixed use-after-free in __ext4_remount in fs/ext4/super.c that could allow a local user to cause an information leak problem while freeing the old quota file names before a potential failure (bsc#1219053).
- CVE-2023-6040: Fixed an out-of-bounds access vulnerability while creating a new netfilter table, lack of a safeguard against invalid nf_tables family (pf) values within `nf_tables_newtable` function (bsc#1218752).
- CVE-2024-0641: Fixed a denial of service vulnerability in tipc_crypto_key_revoke in net/tipc/crypto.c (bsc#1218916).
- CVE-2024-0565: Fixed an out-of-bounds memory read flaw in receive_encrypted_standard in fs/smb/client/smb2ops.c (bsc#1218832).
- CVE-2023-6915: Fixed a NULL pointer dereference problem in ida_free in lib/idr.c (bsc#1218804).
- CVE-2023-51782: Fixed use-after-free in rose_ioctl in net/rose/af_rose.c because of a rose_accept race condition (bsc#1218757).
- CVE-2023-6531: Fixed a use-after-free flaw due to a race problem in the unix garbage collector's deletion of SKB races with unix_stream_read_generic()on the socket that the SKB is queued on (bsc#1218447).
- CVE-2024-0340: Fixed information disclosure in vhost/vhost.c:vhost_new_msg() (bsc#1218689).
- CVE-2024-24860: Fixed a denial of service caused by a race ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb", rpm:"cluster-md-kmp-64kb~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb", rpm:"dlm-kmp-64kb~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-allwinner", rpm:"dtb-allwinner~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-altera", rpm:"dtb-altera~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amazon", rpm:"dtb-amazon~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amd", rpm:"dtb-amd~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amlogic", rpm:"dtb-amlogic~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apm", rpm:"dtb-apm~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apple", rpm:"dtb-apple~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-arm", rpm:"dtb-arm~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-broadcom", rpm:"dtb-broadcom~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-cavium", rpm:"dtb-cavium~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-exynos", rpm:"dtb-exynos~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-freescale", rpm:"dtb-freescale~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-hisilicon", rpm:"dtb-hisilicon~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-lg", rpm:"dtb-lg~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-marvell", rpm:"dtb-marvell~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-mediatek", rpm:"dtb-mediatek~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-nvidia", rpm:"dtb-nvidia~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-qcom", rpm:"dtb-qcom~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-renesas", rpm:"dtb-renesas~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-rockchip", rpm:"dtb-rockchip~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-socionext", rpm:"dtb-socionext~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-sprd", rpm:"dtb-sprd~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-xilinx", rpm:"dtb-xilinx~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb", rpm:"gfs2-kmp-64kb~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-livepatch-devel", rpm:"kernel-64kb-livepatch-devel~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional", rpm:"kernel-64kb-optional~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-livepatch-devel", rpm:"kernel-debug-livepatch-devel~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso", rpm:"kernel-debug-vdso~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150500.55.49.1.150500.6.21.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~5.14.21~150500.55.49.1.150500.6.21.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch-devel", rpm:"kernel-default-livepatch-devel~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional", rpm:"kernel-default-optional~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-livepatch-devel", rpm:"kernel-kvmsmall-livepatch-devel~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb", rpm:"kselftests-kmp-64kb~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb", rpm:"ocfs2-kmp-64kb~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb", rpm:"reiserfs-kmp-64kb~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150500.55.49.1", rls:"openSUSELeap15.5"))) {
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
