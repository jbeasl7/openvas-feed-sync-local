# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.0034.1");
  script_cve_id("CVE-2021-46936", "CVE-2021-47163", "CVE-2021-47416", "CVE-2021-47612", "CVE-2022-48788", "CVE-2022-48789", "CVE-2022-48790", "CVE-2022-48809", "CVE-2022-48946", "CVE-2022-48949", "CVE-2022-48951", "CVE-2022-48956", "CVE-2022-48958", "CVE-2022-48960", "CVE-2022-48962", "CVE-2022-48966", "CVE-2022-48967", "CVE-2022-48969", "CVE-2022-48971", "CVE-2022-48972", "CVE-2022-48973", "CVE-2022-48978", "CVE-2022-48985", "CVE-2022-48988", "CVE-2022-48991", "CVE-2022-48992", "CVE-2022-48997", "CVE-2022-49000", "CVE-2022-49002", "CVE-2022-49010", "CVE-2022-49011", "CVE-2022-49014", "CVE-2022-49015", "CVE-2022-49020", "CVE-2022-49021", "CVE-2022-49026", "CVE-2022-49027", "CVE-2022-49028", "CVE-2022-49029", "CVE-2023-46343", "CVE-2023-52881", "CVE-2023-52898", "CVE-2023-52918", "CVE-2023-52919", "CVE-2023-6270", "CVE-2024-26804", "CVE-2024-27043", "CVE-2024-38538", "CVE-2024-39476", "CVE-2024-40965", "CVE-2024-41016", "CVE-2024-41082", "CVE-2024-42114", "CVE-2024-42145", "CVE-2024-42253", "CVE-2024-44931", "CVE-2024-44958", "CVE-2024-46724", "CVE-2024-46755", "CVE-2024-46802", "CVE-2024-46809", "CVE-2024-46813", "CVE-2024-46816", "CVE-2024-46818", "CVE-2024-46826", "CVE-2024-46834", "CVE-2024-46840", "CVE-2024-46841", "CVE-2024-46848", "CVE-2024-47670", "CVE-2024-47672", "CVE-2024-47673", "CVE-2024-47674", "CVE-2024-47684", "CVE-2024-47685", "CVE-2024-47696", "CVE-2024-47697", "CVE-2024-47698", "CVE-2024-47706", "CVE-2024-47707", "CVE-2024-47713", "CVE-2024-47735", "CVE-2024-47737", "CVE-2024-47742", "CVE-2024-47745", "CVE-2024-47749", "CVE-2024-49851", "CVE-2024-49860", "CVE-2024-49877", "CVE-2024-49881", "CVE-2024-49882", "CVE-2024-49883", "CVE-2024-49890", "CVE-2024-49891", "CVE-2024-49894", "CVE-2024-49896", "CVE-2024-49901", "CVE-2024-49920", "CVE-2024-49929", "CVE-2024-49936", "CVE-2024-49949", "CVE-2024-49957", "CVE-2024-49958", "CVE-2024-49959", "CVE-2024-49962", "CVE-2024-49965", "CVE-2024-49966", "CVE-2024-49967", "CVE-2024-49982", "CVE-2024-49991", "CVE-2024-49995", "CVE-2024-49996", "CVE-2024-50006", "CVE-2024-50007", "CVE-2024-50024", "CVE-2024-50033", "CVE-2024-50035", "CVE-2024-50045", "CVE-2024-50047", "CVE-2024-50058");
  script_tag(name:"creation_date", value:"2025-01-09 04:17:27 +0000 (Thu, 09 Jan 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:0034-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0034-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20250034-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1213034");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219125");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1220439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223824");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225189");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225336");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226606");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227437");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228410");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228564");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228620");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1228743");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229005");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229154");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1229837");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230405");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1230802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231094");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231096");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231115");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231197");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231375");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231539");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231540");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231859");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231864");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231888");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231889");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231890");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231897");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231914");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231929");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231935");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231938");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231939");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231954");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231987");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1231998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232006");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232007");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232016");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232035");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232037");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232038");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232039");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232069");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232070");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232071");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232089");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232111");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232123");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232133");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232134");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232135");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232142");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232172");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232175");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232191");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232200");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232201");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232218");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232221");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232282");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232304");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232305");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232314");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232392");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232394");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232418");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1232442");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-January/020071.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2025:0034-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

The Linux Enterprise 12 SP5 kernel turned LTSS (Extended Security)

The following security bugs were fixed:

- CVE-2021-46936: Fixed use-after-free in tw_timer_handler() (bsc#1220439).
- CVE-2021-47163: kABI fix for tipc: wait and exit until all work queues are done (bsc#1221980).
- CVE-2021-47612: nfc: fix segfault in nfc_genl_dump_devices_done (bsc#1226585).
- CVE-2022-48809: net: fix a memleak when uncloning an skb dst and its metadata (bsc#1227947).
- CVE-2022-48951: ASoC: ops: Correct bounds check for second channel on SX controls (bsc#1231929).
- CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1231893).
- CVE-2022-48958: ethernet: aeroflex: fix potential skb leak in greth_init_rings() (bsc#1231889).
- CVE-2022-48960: net: hisilicon: Fix potential use-after-free in hix5hd2_rx() (bsc#1231979).
- CVE-2022-48962: net: hisilicon: Fix potential use-after-free in hisi_femac_rx() (bsc#1232286).
- CVE-2022-48966: net: mvneta: Fix an out of bounds check (bsc#1232191).
- CVE-2022-48967: NFC: nci: Bounds check struct nfc_target arrays (bsc#1232304).
- CVE-2022-48971: Bluetooth: Fix not cleanup led when bt_init fails (bsc#1232037).
- CVE-2022-48972: mac802154: fix missing INIT_LIST_HEAD in ieee802154_if_add() (bsc#1232025).
- CVE-2022-48973: gpio: amd8111: Fix PCI device reference count leak (bsc#1232039).
- CVE-2022-48978: HID: core: fix shift-out-of-bounds in hid_report_raw_event (bsc#1232038).
- CVE-2022-48991: mm/khugepaged: invoke MMU notifiers in shmem/file collapse paths (bsc#1232070).
- CVE-2022-48992: ASoC: soc-pcm: Add NULL check in BE reparenting (bsc#1232071).
- CVE-2022-49000: iommu/vt-d: Fix PCI device refcount leak in has_external_pci() (bsc#1232123).
- CVE-2022-49002: iommu/vt-d: Fix PCI device refcount leak in dmar_dev_scope_init() (bsc#1232133).
- CVE-2022-49010: hwmon: (coretemp) Check for null before removing sysfs attrs (bsc#1232172).
- CVE-2022-49011: hwmon: (coretemp) fix pci device refcount leak in nv1a_ram_new() (bsc#1232006).
- CVE-2022-49014: net: tun: Fix use-after-free in tun_detach() (bsc#1231890).
- CVE-2022-49015: net: hsr: Fix potential use-after-free (bsc#1231938).
- CVE-2022-49020: net/9p: Fix a potential socket leak in p9_socket_open (bsc#1232175).
- CVE-2022-49021: net: phy: fix null-ptr-deref while probe() failed (bsc#1231939).
- CVE-2022-49026: e100: Fix possible use after free in e100_xmit_prepare (bsc#1231997).
- CVE-2022-49027: iavf: Fix error handling in iavf_init_module() (bsc#1232007).
- CVE-2022-49028: ixgbevf: Fix resource leak in ixgbevf_init_module() (bsc#1231996).
- CVE-2022-49029: hwmon: (ibmpex) Fix possible UAF when ibmpex_register_bmc() fails (bsc#1231995).
- CVE-2023-52898: xhci: Fix null pointer dereference when host dies (bsc#1229568).
- CVE-2023-52918: media: pci: cx23885: check cx23885_vdev_init() return ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cluster-md-kmp-default", rpm:"cluster-md-kmp-default~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dlm-kmp-default", rpm:"dlm-kmp-default~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gfs2-kmp-default", rpm:"gfs2-kmp-default~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocfs2-kmp-default", rpm:"ocfs2-kmp-default~4.12.14~122.234.1", rls:"SLES12.0SP5"))) {
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
