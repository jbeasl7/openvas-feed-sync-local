# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2969");
  script_cve_id("CVE-2022-48816", "CVE-2022-48867", "CVE-2022-48887", "CVE-2023-52653", "CVE-2023-52664", "CVE-2023-52791", "CVE-2023-52880", "CVE-2023-52889", "CVE-2023-52903", "CVE-2024-26921", "CVE-2024-33621", "CVE-2024-35898", "CVE-2024-35976", "CVE-2024-36017", "CVE-2024-36929", "CVE-2024-39507", "CVE-2024-40945", "CVE-2024-40958", "CVE-2024-40959", "CVE-2024-40961", "CVE-2024-40999", "CVE-2024-41073", "CVE-2024-42067", "CVE-2024-42068", "CVE-2024-42265", "CVE-2024-42286", "CVE-2024-42288", "CVE-2024-42289", "CVE-2024-42292", "CVE-2024-42301", "CVE-2024-42312", "CVE-2024-43819", "CVE-2024-43829", "CVE-2024-43834", "CVE-2024-43835", "CVE-2024-43846", "CVE-2024-43853", "CVE-2024-43854", "CVE-2024-43855", "CVE-2024-43856", "CVE-2024-43863", "CVE-2024-43871", "CVE-2024-43880", "CVE-2024-43882", "CVE-2024-43889", "CVE-2024-43890", "CVE-2024-43892", "CVE-2024-43893", "CVE-2024-43894", "CVE-2024-43900", "CVE-2024-43914", "CVE-2024-44931", "CVE-2024-44935", "CVE-2024-44944", "CVE-2024-44947", "CVE-2024-44948", "CVE-2024-44986", "CVE-2024-44987", "CVE-2024-44989", "CVE-2024-44990", "CVE-2024-44995", "CVE-2024-45003", "CVE-2024-45006", "CVE-2024-45008", "CVE-2024-45016", "CVE-2024-45021", "CVE-2024-45025", "CVE-2024-46673", "CVE-2024-46679", "CVE-2024-46681", "CVE-2024-46695", "CVE-2024-46702", "CVE-2024-46707", "CVE-2024-46713", "CVE-2024-46715", "CVE-2024-46719", "CVE-2024-46721", "CVE-2024-46732", "CVE-2024-46737", "CVE-2024-46738", "CVE-2024-46739", "CVE-2024-46743", "CVE-2024-46744", "CVE-2024-46750", "CVE-2024-46770", "CVE-2024-46777", "CVE-2024-46783", "CVE-2024-46787", "CVE-2024-46800", "CVE-2024-46813", "CVE-2024-46814", "CVE-2024-46815", "CVE-2024-46816", "CVE-2024-46822", "CVE-2024-46826", "CVE-2024-46829", "CVE-2024-46834", "CVE-2024-46848", "CVE-2024-46857", "CVE-2024-46859", "CVE-2024-47660", "CVE-2024-47671", "CVE-2024-47685", "CVE-2024-47698", "CVE-2024-47706", "CVE-2024-49855", "CVE-2024-49860", "CVE-2024-49894", "CVE-2024-49996", "CVE-2024-50035", "CVE-2024-50036");
  script_tag(name:"creation_date", value:"2024-12-12 04:32:26 +0000 (Thu, 12 Dec 2024)");
  script_version("2024-12-12T09:30:20+0000");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2969)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2969");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2969");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2969 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel:SUNRPC: fix a memleak in gss_import_v2_context(CVE-2023-52653)

apparmor: Fix null pointer deref when receiving skb during sock creation(CVE-2023-52889)

protect the fetch of ->fd[fd] in do_dup2() from mispredictions(CVE-2024-42265)

tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc(CVE-2023-52880)

padata: Fix possible divide-by-0 panic in padata_mt_helper()(CVE-2024-43889)

dev/parport: fix the array out-of-bounds risk(CVE-2024-42301)

netfilter: ctnetlink: use helper function to calculate expect ID(CVE-2024-44944)

netns: Make get_net_ns() handle zero refcount net(CVE-2024-40958)

ipv6: fix possible UAF in ip6_finish_output2()(CVE-2024-44986)

kvm: s390: Reject memory region operations for ucontrol VMs(CVE-2024-43819)

scsi: qla2xxx: validate nvme_local_port correctly(CVE-2024-42286)

scsi: qla2xxx: During vport delete send async logout explicitly(CVE-2024-42289)

gpio: prevent potential speculation leaks in gpio_device_get_desc()(CVE-2024-44931)

ipv6: prevent possible NULL deref in fib6_nh_init()(CVE-2024-40961)

cgroup/cpuset: Prevent UAF in proc_cpuset_show()(CVE-2024-43853)

tracing: Fix overflow in get_free_elt()(CVE-2024-43890)

exec: Fix ToCToU between perm check and set-uid/gid usage(CVE-2024-43882)

drm/vmwgfx: Fix a deadlock in dma buf fence polling(CVE-2024-43863)

io_uring: lock overflowing for IOPOLL(CVE-2023-52903)

serial: core: check uartclk for zero to avoid divide by zero(CVE-2024-43893)

sysctl: always initialize i_uid/i_gid(CVE-2024-42312)

md/raid5: avoid BUG_ON() while continue reshape after reassembling(CVE-2024-43914)

memcg: protect concurrent access to mem_cgroup_idr(CVE-2024-43892)

scsi: qla2xxx: Fix for possible memory corruption(CVE-2024-42288)

dmaengine: idxd: Prevent use after free on completion memory(CVE-2022-48867)

x86/mtrr: Check if fixed MTRRs exist before saving them(CVE-2024-44948)

dma: fix call order in dmam_free_coherent(CVE-2024-43856)

block: initialize integrity buffer to zero before writing it to media(CVE-2024-43854)

media: xc2028: avoid use-after-free in load_firmware_cb()(CVE-2024-43900)

devres: Fix memory leakage caused by driver API devm_free_percpu()(CVE-2024-43871)

lib: objagg: Fix general protection fault(CVE-2024-43846)

xhci: Fix Panther point NULL pointer deref at full-speed re-enumeration(CVE-2024-45006)

kobject_uevent: Fix OOB access within zap_modalias_env()(CVE-2024-42292)

drm/client: fix null pointer dereference in drm_client_modeset_probe(CVE-2024-43894)

drm/qxl: Add check for drm_cvt_mode(CVE-2024-43829)

userfaultfd: fix checks for huge PMDs(CVE-2024-46787)

md: fix deadlock between mddev_suspend and flush bio(CVE-2024-43855)

udf: Avoid excessive partition lengths(CVE-2024-46777)

uio_hv_generic: Fix kernel NULL pointer dereference in hv_uio_rescind (CVE-2024-46739)

In the Linux kernel, the following vulnerability has been resolved:memcg_write_event_control(): fix a ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1674.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1674.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1674.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1674.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1674.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1674.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
