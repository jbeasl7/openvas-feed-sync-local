# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2072");
  script_cve_id("CVE-2022-49647", "CVE-2022-49787", "CVE-2022-49826", "CVE-2022-49846", "CVE-2022-49870", "CVE-2022-49948", "CVE-2022-49964", "CVE-2022-50109", "CVE-2022-50202", "CVE-2022-50222", "CVE-2023-53091", "CVE-2023-53116", "CVE-2025-21759", "CVE-2025-21760", "CVE-2025-21761", "CVE-2025-21762", "CVE-2025-21763", "CVE-2025-21764", "CVE-2025-21863", "CVE-2025-21999", "CVE-2025-22058", "CVE-2025-23150", "CVE-2025-37839", "CVE-2025-37995");
  script_tag(name:"creation_date", value:"2025-09-10 04:27:54 +0000 (Wed, 10 Sep 2025)");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-13 21:13:44 +0000 (Thu, 13 Mar 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2072)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2072");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2072");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2072 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ext4: update s_journal_inum if it changes after journal replay(CVE-2023-53091)

arp: use RCU protection in arp_xmit().(CVE-2025-21762)

io_uring: prevent opcode speculation(CVE-2025-21863)

jbd2: remove wrong sb->s_sequence check(CVE-2025-37839)

udf: Fix a slab-out-of-bounds write bug in udf_find_entry().(CVE-2022-49846)

udp: Fix memory accounting leak.(CVE-2025-22058)

nvmet: avoid potential UAF in nvmet_req_complete().(CVE-2023-53116)

ext4: fix off-by-one error in do_split(CVE-2025-23150)

cgroup: Use separate src/dst nodes when preloading css_sets for migration(CVE-2022-49647)

PM: hibernate: defer device probing when resuming from hibernation(CVE-2022-50202)

video: fbdev: amba-clcd: Fix refcount leak bugs(CVE-2022-50109)

mmc: sdhci-pci: Fix possible memory leak caused by missing pci_dev_put().(CVE-2022-49787)

capabilities: fix undefined behavior in bit shift for CAP_TO_MASK(CVE-2022-49870)

tty: vt: initialize unicode screen buffer(CVE-2022-50222)

ndisc: extend RCU protection in ndisc_send_skb().(CVE-2025-21760)

ndisc: use RCU protection in ndisc_alloc_skb().(CVE-2025-21764)

ata: libata-transport: fix double ata_host_put() in ata_tport_add().(CVE-2022-49826)

proc: fix UAF in proc_get_inode().(CVE-2025-21999)

vt: Clear selection before changing the font(CVE-2022-49948)

module: ensure that kobject_put() is safe for module type kobjects(CVE-2025-37995)

openvswitch: use RCU protection in ovs_vport_cmd_fill_info().(CVE-2025-21761)

arm64: cacheinfo: Fix incorrect assignment of signed error value to unsigned fw_level(CVE-2022-49964)

neighbour: use RCU protection in __neigh_notify().(CVE-2025-21763)

ipv6: mcast: extend RCU protection in igmp6_send().(CVE-2025-21759)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h2056.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h2056.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h2056.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h2056.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h2056.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
