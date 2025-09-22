# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1042");
  script_cve_id("CVE-2019-0136", "CVE-2019-15504", "CVE-2019-16089", "CVE-2019-16233", "CVE-2019-16234", "CVE-2019-16714", "CVE-2019-16746", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17075", "CVE-2019-17133", "CVE-2019-17666", "CVE-2019-18683", "CVE-2019-18786", "CVE-2019-18806", "CVE-2019-18808", "CVE-2019-18809", "CVE-2019-18813", "CVE-2019-18814", "CVE-2019-19045", "CVE-2019-19049", "CVE-2019-19051", "CVE-2019-19052", "CVE-2019-19054", "CVE-2019-19056", "CVE-2019-19057", "CVE-2019-19058", "CVE-2019-19059", "CVE-2019-19063", "CVE-2019-19065", "CVE-2019-19066", "CVE-2019-19067", "CVE-2019-19068", "CVE-2019-19070", "CVE-2019-19071", "CVE-2019-19072", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19075", "CVE-2019-19077", "CVE-2019-19078", "CVE-2019-19079", "CVE-2019-19080", "CVE-2019-19081", "CVE-2019-19082", "CVE-2019-19083");
  script_tag(name:"creation_date", value:"2020-01-23 13:17:18 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-08 18:09:44 +0000 (Fri, 08 Nov 2019)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2020-1042)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.5\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1042");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1042");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2020-1042 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"drivers/net/wireless/rsi/rsi_91x_usb.c in the Linux kernel through 5.2.9 has a Double Free via crafted USB device traffic (which may be remote via usbip or usbredir).(CVE-2019-15504)

In the Linux kernel before 5.2.14, rds6_inc_info_copy in net/rds/recv.c allows attackers to obtain sensitive information from kernel stack memory because tos and flags fields are not initialized.(CVE-2019-16714)

drivers/scsi/qla2xxx/qla_os.c in the Linux kernel 5.2.14 does not check the alloc_workqueue return value, leading to a NULL pointer dereference.(CVE-2019-16233)

An issue was discovered in the Linux kernel through 5.2.13. nbd_genl_status in drivers/block/nbd.c does not check the nla_nest_start_noflag return value.(CVE-2019-16089)

llcp_sock_create in net/nfc/llcp_sock.c in the AF_NFC network module in the Linux kernel through 5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka CID-3a359798b176.(CVE-2019-17056)

base_sock_create in drivers/isdn/mISDN/socket.c in the AF_ISDN network module in the Linux kernel through 5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka CID-b91ee4aa2a21.(CVE-2019-17055)

atalk_create in net/appletalk/ddp.c in the AF_APPLETALK network module in the Linux kernel through 5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka CID-6cc03e8aa36c.(CVE-2019-17054)

ieee802154_create in net/ieee802154/socket.c in the AF_IEEE802154 network module in the Linux kernel through 5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka CID-e69dbd4619e7.(CVE-2019-17053)

ax25_create in net/ax25/af_ax25.c in the AF_AX25 network module in the Linux kernel through 5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka CID-0614e2b73768.(CVE-2019-17052)

An issue was discovered in write_tpt_entry in drivers/infiniband/hw/cxgb4/mem.c in the Linux kernel through 5.3.2. The cxgb4 driver is directly calling dma_map_single (a DMA function) from a stack variable. This could allow an attacker to trigger a Denial of Service, exploitable if this driver is used on an architecture for which this stack/DMA interaction has security relevance.(CVE-2019-17075)

rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux kernel through 5.3.6 lacks a certain upper-bound check, leading to a buffer overflow.(CVE-2019-17666)

In the Linux kernel through 5.3.2, cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c does not reject a long SSID IE, leading to a Buffer Overflow.(CVE-2019-17133)

An issue was discovered in net/wireless/nl80211.c in the Linux kernel through 5.2.17. It does not check the length of variable elements in a beacon head, leading to a buffer overflow.(CVE-2019-16746)

Insufficient access control in the Intel(R) PROSet/Wireless WiFi ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.5.0.");

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

if(release == "EULEROSVIRTARM64-3.0.5.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h619.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h619.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h619.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h619.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h619.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.36~vhulk1907.1.0.h619.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~vhulk1907.1.0.h619.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~vhulk1907.1.0.h619.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.36~vhulk1907.1.0.h619.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.5.0"))) {
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
