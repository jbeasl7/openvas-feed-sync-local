# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2360.1");
  script_cve_id("CVE-2020-10135", "CVE-2021-43389", "CVE-2021-4439", "CVE-2021-47103", "CVE-2021-47191", "CVE-2021-47193", "CVE-2021-47267", "CVE-2021-47270", "CVE-2021-47293", "CVE-2021-47294", "CVE-2021-47297", "CVE-2021-47309", "CVE-2021-47328", "CVE-2021-47354", "CVE-2021-47372", "CVE-2021-47379", "CVE-2021-47407", "CVE-2021-47418", "CVE-2021-47434", "CVE-2021-47445", "CVE-2021-47518", "CVE-2021-47544", "CVE-2021-47566", "CVE-2021-47571", "CVE-2021-47576", "CVE-2021-47587", "CVE-2021-47589", "CVE-2021-47600", "CVE-2021-47602", "CVE-2021-47603", "CVE-2021-47609", "CVE-2021-47617", "CVE-2022-0435", "CVE-2022-22942", "CVE-2022-48711", "CVE-2022-48715", "CVE-2022-48722", "CVE-2022-48732", "CVE-2022-48733", "CVE-2022-48740", "CVE-2022-48743", "CVE-2022-48754", "CVE-2022-48756", "CVE-2022-48758", "CVE-2022-48759", "CVE-2022-48760", "CVE-2022-48761", "CVE-2022-48771", "CVE-2022-48772", "CVE-2023-24023", "CVE-2023-52622", "CVE-2023-52675", "CVE-2023-52737", "CVE-2023-52752", "CVE-2023-52754", "CVE-2023-52757", "CVE-2023-52762", "CVE-2023-52764", "CVE-2023-52784", "CVE-2023-52808", "CVE-2023-52809", "CVE-2023-52811", "CVE-2023-52832", "CVE-2023-52834", "CVE-2023-52835", "CVE-2023-52843", "CVE-2023-52845", "CVE-2023-52855", "CVE-2023-52881", "CVE-2024-26633", "CVE-2024-26641", "CVE-2024-26679", "CVE-2024-26687", "CVE-2024-26720", "CVE-2024-26813", "CVE-2024-26845", "CVE-2024-26863", "CVE-2024-26894", "CVE-2024-26923", "CVE-2024-26928", "CVE-2024-26973", "CVE-2024-27399", "CVE-2024-27410", "CVE-2024-35247", "CVE-2024-35807", "CVE-2024-35822", "CVE-2024-35835", "CVE-2024-35862", "CVE-2024-35863", "CVE-2024-35864", "CVE-2024-35865", "CVE-2024-35867", "CVE-2024-35868", "CVE-2024-35870", "CVE-2024-35886", "CVE-2024-35896", "CVE-2024-35922", "CVE-2024-35925", "CVE-2024-35930", "CVE-2024-35950", "CVE-2024-35956", "CVE-2024-35958", "CVE-2024-35960", "CVE-2024-35962", "CVE-2024-35976", "CVE-2024-35979", "CVE-2024-35997", "CVE-2024-35998", "CVE-2024-36016", "CVE-2024-36017", "CVE-2024-36025", "CVE-2024-36479", "CVE-2024-36592", "CVE-2024-36880", "CVE-2024-36894", "CVE-2024-36915", "CVE-2024-36917", "CVE-2024-36919", "CVE-2024-36923", "CVE-2024-36934", "CVE-2024-36938", "CVE-2024-36940", "CVE-2024-36949", "CVE-2024-36950", "CVE-2024-36960", "CVE-2024-36964", "CVE-2024-37021", "CVE-2024-37354", "CVE-2024-38544", "CVE-2024-38545", "CVE-2024-38546", "CVE-2024-38549", "CVE-2024-38552", "CVE-2024-38553", "CVE-2024-38565", "CVE-2024-38567", "CVE-2024-38578", "CVE-2024-38579", "CVE-2024-38580", "CVE-2024-38597", "CVE-2024-38601", "CVE-2024-38608", "CVE-2024-38618", "CVE-2024-38621", "CVE-2024-38627", "CVE-2024-38659", "CVE-2024-38661", "CVE-2024-38780");
  script_tag(name:"creation_date", value:"2024-07-10 04:28:31 +0000 (Wed, 10 Jul 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 19:43:55 +0000 (Thu, 07 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2360-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2360-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242360-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1119113");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171988");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195775");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1204514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216062");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1217912");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219224");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221647");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221654");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221791");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1221958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222080");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222364");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222385");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222435");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222809");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223013");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223532");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223641");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224177");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224432");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224504");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224549");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224552");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224588");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224605");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224661");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224662");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224664");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224668");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224677");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224703");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224739");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224978");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1224997");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225184");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225306");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225337");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225463");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225484");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225490");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225514");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225559");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225583");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225599");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225611");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225642");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225704");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225760");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225761");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225815");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225848");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225866");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225894");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1225898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226211");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226537");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226554");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226557");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226562");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226567");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226575");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226577");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226595");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226610");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226614");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226619");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226634");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226670");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226692");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226701");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226705");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226708");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226711");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226712");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226716");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226732");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226744");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226749");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226754");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226857");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226883");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226886");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226895");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226949");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226962");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1226996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227101");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/035874.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2024:2360-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security bugfixes.


The following security bugs were fixed:

- CVE-2021-47103: net: sock: preserve kabi for sock (bsc#1221010).
- CVE-2021-47191: Fix out-of-bound read in resp_readcap16() (bsc#1222866).
- CVE-2021-47267: usb: fix various gadget panics on 10gbps cabling (bsc#1224993).
- CVE-2021-47270: usb: fix various gadgets null ptr deref on 10gbps cabling (bsc#1224997).
- CVE-2021-47293: net/sched: act_skbmod: Skip non-Ethernet packets (bsc#1224978).
- CVE-2021-47294: netrom: Decrease sock refcount when sock timers expire (bsc#1224977).
- CVE-2021-47297: net: fix uninit-value in caif_seqpkt_sendmsg (bsc#1224976).
- CVE-2021-47309: net: validate lwtstate->data before returning from skb_tunnel_info() (bsc#1224967).
- CVE-2021-47354: drm/sched: Avoid data corruptions (bsc#1225140)
- CVE-2021-47372: net: macb: fix use after free on rmmod (bsc#1225184).
- CVE-2021-47379: blk-cgroup: fix UAF by grabbing blkcg lock before destroying blkg pd (bsc#1225203).
- CVE-2021-47407: KVM: x86: Handle SRCU initialization failure during page track init (bsc#1225306).
- CVE-2021-47418: net_sched: fix NULL deref in fifo_set_limit() (bsc#1225337).
- CVE-2021-47434: xhci: Fix commad ring abort, write all 64 bits to CRCR register (bsc#1225232).
- CVE-2021-47445: drm/msm: Fix null pointer dereference on pointer edp (bsc#1225261)
- CVE-2021-47518: nfc: fix potential NULL pointer deref in nfc_genl_dump_ses_done (bsc#1225372).
- CVE-2021-47544: tcp: fix page frag corruption on page fault (bsc#1225463).
- CVE-2021-47566: Fix clearing user buffer by properly using clear_user() (bsc#1225514).
- CVE-2021-47571: staging: rtl8192e: Fix use after free in _rtl92e_pci_disconnect() (bsc#1225518).
- CVE-2021-47587: net: systemport: Add global locking for descriptor lifecycle (bsc#1226567).
- CVE-2021-47602: mac80211: track only QoS data frames for admission control (bsc#1226554).
- CVE-2021-47609: firmware: arm_scpi: Fix string overflow in SCPI genpd driver (bsc#1226562)
- CVE-2022-48732: drm/nouveau: fix off by one in BIOS boundary checking (bsc#1226716)
- CVE-2022-48733: btrfs: fix use-after-free after failure to create a snapshot (bsc#1226718).
- CVE-2022-48740: selinux: fix double free of cond_list on error paths (bsc#1226699).
- CVE-2022-48743: net: amd-xgbe: Fix skb data length underflow (bsc#1226705).
- CVE-2022-48756: drm/msm/dsi: invalid parameter check in msm_dsi_phy_enable (bsc#1226698)
- CVE-2022-48759: rpmsg: char: Fix race between the release of rpmsg_ctrldev and cdev (bsc#1226711).
- CVE-2022-48761: usb: xhci-plat: fix crash when suspend if remote wake enable (bsc#1226701).
- CVE-2022-48772: media: lgdt3306a: Add a check against null-pointer-def (bsc#1226976).
- CVE-2023-52622: ext4: avoid online resizing failures due to oversized flex bg (bsc#1222080).
- CVE-2023-52675: powerpc/imc-pmu: Add a null pointer check in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.191.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.191.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.191.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.191.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.191.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.191.1", rls:"SLES12.0SP5"))) {
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
