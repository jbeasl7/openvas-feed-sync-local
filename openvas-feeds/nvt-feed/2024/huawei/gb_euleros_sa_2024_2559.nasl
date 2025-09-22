# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2559");
  script_cve_id("CVE-2021-47183", "CVE-2022-48652", "CVE-2022-48744", "CVE-2022-48828", "CVE-2023-52679", "CVE-2023-52754", "CVE-2023-52781", "CVE-2024-23848", "CVE-2024-24859", "CVE-2024-26846", "CVE-2024-26865", "CVE-2024-26878", "CVE-2024-26880", "CVE-2024-26881", "CVE-2024-26891", "CVE-2024-26910", "CVE-2024-27047", "CVE-2024-27062", "CVE-2024-27388", "CVE-2024-27417", "CVE-2024-35805", "CVE-2024-35839", "CVE-2024-35878", "CVE-2024-35884", "CVE-2024-35893", "CVE-2024-35899", "CVE-2024-35947", "CVE-2024-35965", "CVE-2024-35969", "CVE-2024-36005", "CVE-2024-36270", "CVE-2024-36286", "CVE-2024-37356", "CVE-2024-38538", "CVE-2024-38540", "CVE-2024-38541", "CVE-2024-38544", "CVE-2024-38552", "CVE-2024-38555", "CVE-2024-38556", "CVE-2024-38588", "CVE-2024-38590", "CVE-2024-38596", "CVE-2024-38598", "CVE-2024-38608", "CVE-2024-38659", "CVE-2024-39476", "CVE-2024-39480", "CVE-2024-39482", "CVE-2024-39487", "CVE-2024-39494", "CVE-2024-39497", "CVE-2024-39501", "CVE-2024-39509", "CVE-2024-40901", "CVE-2024-40905", "CVE-2024-40934", "CVE-2024-40953", "CVE-2024-40960", "CVE-2024-40966", "CVE-2024-40972", "CVE-2024-40980", "CVE-2024-40983", "CVE-2024-40995", "CVE-2024-41002", "CVE-2024-41005", "CVE-2024-41007", "CVE-2024-41012", "CVE-2024-41013", "CVE-2024-41014", "CVE-2024-41020", "CVE-2024-41023", "CVE-2024-41027", "CVE-2024-41035", "CVE-2024-41041", "CVE-2024-41042", "CVE-2024-41044", "CVE-2024-41048", "CVE-2024-41069", "CVE-2024-41079", "CVE-2024-41080", "CVE-2024-41082", "CVE-2024-41087", "CVE-2024-41089", "CVE-2024-41090", "CVE-2024-41091", "CVE-2024-41098", "CVE-2024-42070", "CVE-2024-42080", "CVE-2024-42082", "CVE-2024-42084", "CVE-2024-42090", "CVE-2024-42096", "CVE-2024-42098", "CVE-2024-42101", "CVE-2024-42106", "CVE-2024-42122", "CVE-2024-42131", "CVE-2024-42145", "CVE-2024-42148", "CVE-2024-42152", "CVE-2024-42154", "CVE-2024-42161", "CVE-2024-42223", "CVE-2024-42229", "CVE-2024-42232", "CVE-2024-42244", "CVE-2024-42246", "CVE-2024-42281", "CVE-2024-42283", "CVE-2024-42284", "CVE-2024-42285", "CVE-2024-42304", "CVE-2024-42321", "CVE-2024-42322", "CVE-2024-43828", "CVE-2024-43830", "CVE-2024-43861", "CVE-2024-43866");
  script_tag(name:"creation_date", value:"2024-10-09 04:31:34 +0000 (Wed, 09 Oct 2024)");
  script_version("2024-10-09T08:09:35+0000");
  script_tag(name:"last_modification", value:"2024-10-09 08:09:35 +0000 (Wed, 09 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-19 19:45:41 +0000 (Mon, 19 Aug 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2559)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2559");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2559");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2559 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition was found in the Linux kernel's net/bluetooth in sniff_{min,max}_interval_set() function. This can result in a bluetooth sniffing exception issue, possibly leading denial of service.(CVE-2024-24859)

bnxt_re: avoid shift undefined behavior in bnxt_qplib_alloc_init_hwq(CVE-2024-38540)

drivers: core: synchronize really_probe() and dev_uevent()(CVE-2024-39501)

drm/amd/display: Fix potential index out of bounds in color transformation function(CVE-2024-38552)

drop_monitor: replace spin_lock by raw_spin_lock(CVE-2024-40980)

dyndbg: fix old BUG_ON in >control parser(CVE-2024-35947)

ext4: do not create EA inode under buffer lock(CVE-2024-40972)

HID: logitech-dj: Fix memory leak in logi_dj_recv_switch_to_dj_mode()(CVE-2024-40934)

ice: Fix crash by keep old cfg when update TCs more than queues(CVE-2022-48652)

In the Linux kernel through 6.7.1, there is a use-after-free in cec_queue_msg_fh, related to drivers/media/cec/core/cec-adap.c and drivers/media/cec/core/cec-api.c.(CVE-2024-23848)

ipv6: fix possible race in __fib6_drop_pcpu_from()(CVE-2024-40905)

ipv6: fix potential 'struct net' leak in inet6_rtm_getaddr()(CVE-2024-27417)

kernel:af_unix: Fix data races in unix_release_sock/unix_stream_sendmsg(CVE-2024-38596)

kernel:bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set()(CVE-2024-39487)

kernel:dm: call the resume method on internal suspend(CVE-2024-26880)

kernel:fix lockup in dm_exception_table_exit There was reported lockup(CVE-2024-35805)

kernel:ftrace: Fix possible use-after-free issue in ftrace_location()(CVE-2024-38588)

kernel:ima: Fix use-after-free on a dentry's dname.name(CVE-2024-39494)

kernel:ipv6: fix race condition between ipv6_get_ifaddr and ipv6_del_addr(CVE-2024-35969)

kernel:ipv6: prevent possible NULL dereference in rt6_probe()(CVE-2024-40960)

kernel:kdb: Fix buffer overflow during tab-complete(CVE-2024-39480)

kernel:net/mlx5e: Avoid field-overflowing memcpy()(CVE-2022-48744)

kernel:net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc()(CVE-2024-40995)

kernel:net: bridge: xmit: make sure we have at least eth header len bytes(CVE-2024-38538)

kernel:netpoll: Fix race condition in netpoll_owner_active(CVE-2024-41005)

kernel:nouveau: lock the client object tree. (CVE-2024-27062)

kernel:nvme-fc: do not wait in vain when unloading module(CVE-2024-26846)

kernel:of: Fix double free in of_parse_phandle_with_args_map(CVE-2023-52679)

kernel:of: module: add buffer overflow check in of_modalias()(CVE-2024-38541)

kernel:scsi: lpfc: Fix link down processing to address NULL pointer dereference(CVE-2021-47183)

kernel:SUNRPC: fix some memleaks in gssx_dec_option_array(CVE-2024-27388)

kernel:tcp: avoid too many retransmit packets(CVE-2024-41007)

kernel:tcp: Fix shift-out-of-bounds in dctcp_update_alpha().(CVE-2024-37356)

md/raid5: fix deadlock that raid5d() wait for itself to clear ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1587.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1587.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1587.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1587.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1587.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1587.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
