# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2476");
  script_cve_id("CVE-2019-25162", "CVE-2021-33631", "CVE-2021-46904", "CVE-2021-46905", "CVE-2021-46906", "CVE-2021-46915", "CVE-2021-46921", "CVE-2021-46928", "CVE-2021-46932", "CVE-2021-46934", "CVE-2021-46936", "CVE-2021-46938", "CVE-2021-46939", "CVE-2021-46945", "CVE-2021-46952", "CVE-2021-46953", "CVE-2021-46955", "CVE-2021-46960", "CVE-2021-46988", "CVE-2021-46992", "CVE-2021-47006", "CVE-2021-47010", "CVE-2021-47013", "CVE-2021-47015", "CVE-2021-47024", "CVE-2021-47054", "CVE-2021-47060", "CVE-2021-47061", "CVE-2021-47063", "CVE-2021-47074", "CVE-2021-47076", "CVE-2021-47077", "CVE-2021-47078", "CVE-2021-47082", "CVE-2021-47091", "CVE-2021-47101", "CVE-2021-47131", "CVE-2021-47142", "CVE-2021-47144", "CVE-2021-47146", "CVE-2021-47166", "CVE-2021-47167", "CVE-2021-47168", "CVE-2021-47170", "CVE-2021-47171", "CVE-2021-47182", "CVE-2021-47194", "CVE-2021-47203", "CVE-2022-48619", "CVE-2022-48627", "CVE-2023-51042", "CVE-2023-51043", "CVE-2023-52340", "CVE-2023-52435", "CVE-2023-52439", "CVE-2023-52458", "CVE-2023-52464", "CVE-2023-52469", "CVE-2023-52477", "CVE-2023-52478", "CVE-2023-52486", "CVE-2023-52515", "CVE-2023-52522", "CVE-2023-52527", "CVE-2023-52528", "CVE-2023-52530", "CVE-2023-52574", "CVE-2023-52578", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52595", "CVE-2023-52597", "CVE-2023-52612", "CVE-2023-52615", "CVE-2023-52619", "CVE-2023-52620", "CVE-2023-52622", "CVE-2023-52623", "CVE-2023-7042", "CVE-2024-0607", "CVE-2024-0775", "CVE-2024-1086", "CVE-2024-1151", "CVE-2024-23307", "CVE-2024-24855", "CVE-2024-25739", "CVE-2024-26597", "CVE-2024-26598", "CVE-2024-26602", "CVE-2024-26614", "CVE-2024-26633", "CVE-2024-26635", "CVE-2024-26640", "CVE-2024-26641", "CVE-2024-26642", "CVE-2024-26645", "CVE-2024-26668", "CVE-2024-26671", "CVE-2024-26675", "CVE-2024-26679", "CVE-2024-26686", "CVE-2024-26704", "CVE-2024-26720", "CVE-2024-26733", "CVE-2024-26735", "CVE-2024-26739", "CVE-2024-26740", "CVE-2024-26743", "CVE-2024-26744", "CVE-2024-26752", "CVE-2024-26759", "CVE-2024-26763", "CVE-2024-26772", "CVE-2024-26773", "CVE-2024-26779", "CVE-2024-26804", "CVE-2024-26805", "CVE-2024-26810", "CVE-2024-26812", "CVE-2024-26813", "CVE-2024-26828", "CVE-2024-26840", "CVE-2024-26845", "CVE-2024-26851", "CVE-2024-26859", "CVE-2024-26872", "CVE-2024-26882", "CVE-2024-26883", "CVE-2024-26884", "CVE-2024-26894", "CVE-2024-26901", "CVE-2024-26915", "CVE-2024-26922", "CVE-2024-27437");
  script_tag(name:"creation_date", value:"2024-09-23 08:46:49 +0000 (Mon, 23 Sep 2024)");
  script_version("2024-09-24T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-09-24 05:05:44 +0000 (Tue, 24 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-29 20:03:04 +0000 (Mon, 29 Apr 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2476)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2476");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2476");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2476 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"IB/ipoib: Fix mcast list locking(CVE-2023-52587)

netfilter: nftables: avoid overflows in nft_hash_buckets()(CVE-2021-46992)

SUNRPC: Fix a suspicious RCU usage warning(CVE-2023-52623)

l2tp: pass correct message length to ip6_append_data(CVE-2024-26752)

net/sched: act_mirred: use the backlog for mirred ingress(CVE-2024-26740)

RDMA/srp: Do not call scsi_done() from srp_abort()(CVE-2023-52515)

hwrng: core - Fix page fault dead lock on mmap-ed hwrng(CVE-2023-52615)

KVM: s390: fix setting of fpc register(CVE-2023-52597)

In the Linux kernel before 6.4.5, drivers/gpu/drm/drm_atomic.c has a use-after-free during a race condition between a nonblocking atomic commit and a driver unload.(CVE-2023-51043)

uio: Fix use-after-free in uio_open(CVE-2023-52439)

A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation.The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT.(CVE-2024-1086)

ACPI: GTDT: Don't corrupt interrupt mappings on watchdow probe failure(CVE-2021-46953)

drivers/amd/pm: fix a use-after-free in kv_parse_power_table(CVE-2023-52469)

KVM: Destroy I/O bus devices on unregister failure _after_ sync'ing SRCU(CVE-2021-47061)

KVM: arm64: vgic-its: Avoid potential UAF in LPI translation cache(CVE-2024-26598)

i2c: validate user data in compat ioctl(CVE-2021-46934)

parisc: Clear stale IIR value on instruction access rights trap(CVE-2021-46928)

net: hso: fix null-ptr-deref during tty device unregistration(CVE-2021-46904)

net: hso: fix NULL-deref on disconnect regression(CVE-2021-46905)

usb: hub: Guard against accesses to uninitialized BOS descriptors(CVE-2023-52477)

EDAC/thunderx: Fix possible out-of-bounds string access(CVE-2023-52464)

cifs: Return correct error code from smb2_get_enc_key(CVE-2021-46960)

openvswitch: fix stack OOB read while fragmenting IPv4 packets(CVE-2021-46955)

ceph: fix deadlock or deadcode of misusing dget()(CVE-2023-52583)

ARM: 9064/1: hw_breakpoint: Do not directly check the event's overflow_handler hook(CVE-2021-47006)

block: add check that partition length needs to be aligned with block size(CVE-2023-52458)

locking/qrwlock: Fix ordering in queued_write_lock_slowpath()(CVE-2021-46921)

The IPv6 implementation in the Linux kernel before 6.3 has a net/ipv6/route.c max_size threshold that can be consumed easily, e.g., leading to a denial of service (network is unreachable errors) when IPv6 packets are sent in a loop via a raw socket.(CVE-2023-52340)

pstore/ram: Fix crash when setting number of cpus to an odd number(CVE-2023-52619)

NFS: fs_context: validate UDP retrans to prevent shift out-of-bounds(CVE-2021-46952)

ext4: always panic when errors=panic is ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.36~vhulk1907.1.0.h1635.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
