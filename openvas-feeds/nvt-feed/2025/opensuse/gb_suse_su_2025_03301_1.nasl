# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.03301.1");
  script_cve_id("CVE-2023-3867", "CVE-2023-4130", "CVE-2023-4515", "CVE-2024-26661", "CVE-2024-46733", "CVE-2024-49996", "CVE-2024-53125", "CVE-2024-58238", "CVE-2024-58239", "CVE-2025-37885", "CVE-2025-38006", "CVE-2025-38075", "CVE-2025-38103", "CVE-2025-38125", "CVE-2025-38146", "CVE-2025-38160", "CVE-2025-38184", "CVE-2025-38185", "CVE-2025-38190", "CVE-2025-38201", "CVE-2025-38205", "CVE-2025-38208", "CVE-2025-38245", "CVE-2025-38251", "CVE-2025-38360", "CVE-2025-38439", "CVE-2025-38441", "CVE-2025-38444", "CVE-2025-38445", "CVE-2025-38458", "CVE-2025-38459", "CVE-2025-38464", "CVE-2025-38472", "CVE-2025-38490", "CVE-2025-38491", "CVE-2025-38499", "CVE-2025-38500", "CVE-2025-38503", "CVE-2025-38506", "CVE-2025-38510", "CVE-2025-38512", "CVE-2025-38513", "CVE-2025-38515", "CVE-2025-38516", "CVE-2025-38520", "CVE-2025-38524", "CVE-2025-38528", "CVE-2025-38529", "CVE-2025-38530", "CVE-2025-38531", "CVE-2025-38535", "CVE-2025-38537", "CVE-2025-38538", "CVE-2025-38540", "CVE-2025-38541", "CVE-2025-38543", "CVE-2025-38546", "CVE-2025-38548", "CVE-2025-38550", "CVE-2025-38553", "CVE-2025-38555", "CVE-2025-38560", "CVE-2025-38563", "CVE-2025-38565", "CVE-2025-38566", "CVE-2025-38568", "CVE-2025-38571", "CVE-2025-38572", "CVE-2025-38576", "CVE-2025-38581", "CVE-2025-38582", "CVE-2025-38583", "CVE-2025-38585", "CVE-2025-38587", "CVE-2025-38588", "CVE-2025-38591", "CVE-2025-38601", "CVE-2025-38602", "CVE-2025-38604", "CVE-2025-38608", "CVE-2025-38609", "CVE-2025-38610", "CVE-2025-38612", "CVE-2025-38617", "CVE-2025-38618", "CVE-2025-38621", "CVE-2025-38624", "CVE-2025-38630", "CVE-2025-38632", "CVE-2025-38634", "CVE-2025-38635", "CVE-2025-38644", "CVE-2025-38646", "CVE-2025-38650", "CVE-2025-38656", "CVE-2025-38663", "CVE-2025-38665", "CVE-2025-38670", "CVE-2025-38671");
  script_tag(name:"creation_date", value:"2025-09-25 04:06:57 +0000 (Thu, 25 Sep 2025)");
  script_version("2025-09-25T05:39:09+0000");
  script_tag(name:"last_modification", value:"2025-09-25 05:39:09 +0000 (Thu, 25 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-25 19:56:10 +0000 (Fri, 25 Oct 2024)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:03301-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03301-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503301-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213545");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234156");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1241353");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1242960");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244930");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245710");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245780");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245956");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247078");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247116");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247155");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247243");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247280");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248164");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248166");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248178");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248183");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248186");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248194");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248196");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248198");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248206");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248208");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248214");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248240");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248297");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248312");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248340");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248341");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248345");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248349");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248350");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248355");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248363");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248374");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248377");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248386");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248390");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248399");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248609");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248617");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248636");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248643");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248652");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249346");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-September/041802.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel' package(s) announced via the SUSE-SU-2025:03301-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2024-46733: btrfs: fix qgroup reserve leaks in cow_file_range (bsc#1230708).
- CVE-2024-49996: cifs: Fix buffer overflow when parsing NFS reparse points (bsc#1232089).
- CVE-2024-53125: bpf: sync_linked_regs() must preserve subreg_def (bsc#1234156).
- CVE-2025-37885: KVM: x86: Reset IRTE to host control if *new* route isn't postable (bsc#1242960).
- CVE-2025-38006: net: mctp: Do not access ifa_index when missing (bsc#1244930).
- CVE-2025-38075: scsi: target: iscsi: Fix timeout on deleted connection (bsc#1244734).
- CVE-2025-38103: HID: usbhid: Eliminate recurrent out-of-bounds bug in usbhid_parse() (bsc#1245663).
- CVE-2025-38125: net: stmmac: make sure that ptp_rate is not 0 before configuring EST (bsc#1245710).
- CVE-2025-38146: net: openvswitch: Fix the dead loop of MPLS parse (bsc#1245767).
- CVE-2025-38160: clk: bcm: rpi: Add NULL check in raspberrypi_clk_register() (bsc#1245780).
- CVE-2025-38184: tipc: fix null-ptr-deref when acquiring remote ip of ethernet bearer (bsc#1245956).
- CVE-2025-38185: atm: atmtcp: Free invalid length skb in atmtcp_c_send() (bsc#1246012).
- CVE-2025-38190: atm: Revert atm_account_tx() if copy_from_iter_full() fails (bsc#1245973).
- CVE-2025-38201: netfilter: nft_set_pipapo: clamp maximum map bucket size to INT_MAX (bsc#1245977).
- CVE-2025-38205: drm/amd/display: Avoid divide by zero by initializing dummy pitch to 1 (bsc#1246005).
- CVE-2025-38208: smb: client: add NULL check in automount_fullpath (bsc#1245815).
- CVE-2025-38245: atm: Release atm_dev_mutex after removing procfs in atm_dev_deregister() (bsc#1246193).
- CVE-2025-38251: atm: clip: prevent NULL deref in clip_push() (bsc#1246181).
- CVE-2025-38360: drm/amd/display: Add more checks for DSC / HUBP ONO guarantees (bsc#1247078).
- CVE-2025-38563: perf/core: Prevent VMA split of buffer mappings (bsc#1248306).
- CVE-2025-38439: bnxt_en: Set DMA unmap len correctly for XDP_REDIRECT (bsc#1247155).
- CVE-2025-38441: netfilter: flowtable: account for Ethernet header in nf_flow_pppoe_proto() (bsc#1247167).
- CVE-2025-38444: raid10: cleanup memleak at raid10_make_request (bsc#1247162).
- CVE-2025-38445: md/raid1: Fix stack memory use after return in raid1_reshape (bsc#1247229).
- CVE-2025-38458: atm: clip: Fix NULL pointer dereference in vcc_sendmsg() (bsc#1247116).
- CVE-2025-38459: atm: clip: Fix infinite recursive call of clip_push() (bsc#1247119).
- CVE-2025-38464: tipc: Fix use-after-free in tipc_conn_close() (bsc#1247112).
- CVE-2025-38472: netfilter: nf_conntrack: fix crash due to removal of uninitialised entry (bsc#1247313).
- CVE-2025-38490: net: libwx: remove duplicate page_pool_put_full_page() (bsc#1247243).
- CVE-2025-38491: mptcp: make fallback action and fallback decision atomic (bsc#1247280).
- CVE-2025-38499: clone_private_mnt(): make ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-64kb", rpm:"cluster-md-kmp-64kb~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-64kb", rpm:"dlm-kmp-64kb~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-allwinner", rpm:"dtb-allwinner~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-altera", rpm:"dtb-altera~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amazon", rpm:"dtb-amazon~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amd", rpm:"dtb-amd~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-amlogic", rpm:"dtb-amlogic~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apm", rpm:"dtb-apm~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-apple", rpm:"dtb-apple~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-arm", rpm:"dtb-arm~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-broadcom", rpm:"dtb-broadcom~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-cavium", rpm:"dtb-cavium~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-exynos", rpm:"dtb-exynos~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-freescale", rpm:"dtb-freescale~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-hisilicon", rpm:"dtb-hisilicon~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-lg", rpm:"dtb-lg~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-marvell", rpm:"dtb-marvell~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-mediatek", rpm:"dtb-mediatek~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-nvidia", rpm:"dtb-nvidia~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-qcom", rpm:"dtb-qcom~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-renesas", rpm:"dtb-renesas~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-rockchip", rpm:"dtb-rockchip~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-socionext", rpm:"dtb-socionext~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-sprd", rpm:"dtb-sprd~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dtb-xilinx", rpm:"dtb-xilinx~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-64kb", rpm:"gfs2-kmp-64kb~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-extra", rpm:"kernel-64kb-extra~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-optional", rpm:"kernel-64kb-optional~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-vdso", rpm:"kernel-debug-vdso~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~6.4.0~150600.23.70.1.150600.12.30.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-rebuild", rpm:"kernel-default-base-rebuild~6.4.0~150600.23.70.1.150600.12.30.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch", rpm:"kernel-default-livepatch~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-livepatch-devel", rpm:"kernel-default-livepatch-devel~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-optional", rpm:"kernel-default-optional~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-vdso", rpm:"kernel-default-vdso~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall", rpm:"kernel-kvmsmall~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-devel", rpm:"kernel-kvmsmall-devel~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kvmsmall-vdso", rpm:"kernel-kvmsmall-vdso~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-64kb", rpm:"kselftests-kmp-64kb~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kselftests-kmp-default", rpm:"kselftests-kmp-default~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-64kb", rpm:"ocfs2-kmp-64kb~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-64kb", rpm:"reiserfs-kmp-64kb~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~6.4.0~150600.23.70.1", rls:"openSUSELeap15.6"))) {
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
