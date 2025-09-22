# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2938");
  script_cve_id("CVE-2022-48748", "CVE-2022-48757", "CVE-2022-48867", "CVE-2022-48887", "CVE-2022-48939", "CVE-2022-49006", "CVE-2023-52664", "CVE-2023-52880", "CVE-2023-52889", "CVE-2023-52917", "CVE-2023-6356", "CVE-2023-6535", "CVE-2024-26820", "CVE-2024-26852", "CVE-2024-27414", "CVE-2024-33621", "CVE-2024-35898", "CVE-2024-35976", "CVE-2024-36017", "CVE-2024-36484", "CVE-2024-36929", "CVE-2024-39507", "CVE-2024-40945", "CVE-2024-40958", "CVE-2024-40959", "CVE-2024-40961", "CVE-2024-40999", "CVE-2024-42286", "CVE-2024-42287", "CVE-2024-42288", "CVE-2024-42292", "CVE-2024-42301", "CVE-2024-42312", "CVE-2024-43819", "CVE-2024-43829", "CVE-2024-43834", "CVE-2024-43835", "CVE-2024-43845", "CVE-2024-43854", "CVE-2024-43855", "CVE-2024-43856", "CVE-2024-43863", "CVE-2024-43871", "CVE-2024-43872", "CVE-2024-43880", "CVE-2024-43889", "CVE-2024-43890", "CVE-2024-43892", "CVE-2024-43893", "CVE-2024-43894", "CVE-2024-43900", "CVE-2024-43914", "CVE-2024-44931", "CVE-2024-44934", "CVE-2024-44935", "CVE-2024-44944", "CVE-2024-44948", "CVE-2024-44952", "CVE-2024-44958", "CVE-2024-44986", "CVE-2024-44987", "CVE-2024-44989", "CVE-2024-44990", "CVE-2024-44995", "CVE-2024-45003", "CVE-2024-45006", "CVE-2024-45008", "CVE-2024-45016", "CVE-2024-45018", "CVE-2024-45021", "CVE-2024-45025", "CVE-2024-46673", "CVE-2024-46678", "CVE-2024-46679", "CVE-2024-46681", "CVE-2024-46695", "CVE-2024-46702", "CVE-2024-46707", "CVE-2024-46713", "CVE-2024-46715", "CVE-2024-46719", "CVE-2024-46721", "CVE-2024-46732", "CVE-2024-46733", "CVE-2024-46737", "CVE-2024-46738", "CVE-2024-46739", "CVE-2024-46743", "CVE-2024-46744", "CVE-2024-46750", "CVE-2024-46770", "CVE-2024-46777", "CVE-2024-46783", "CVE-2024-46787", "CVE-2024-46800", "CVE-2024-46813", "CVE-2024-46814", "CVE-2024-46815", "CVE-2024-46816", "CVE-2024-46822", "CVE-2024-46826", "CVE-2024-46829", "CVE-2024-46833", "CVE-2024-46834", "CVE-2024-46848", "CVE-2024-46855", "CVE-2024-46857", "CVE-2024-46859", "CVE-2024-47660", "CVE-2024-47671", "CVE-2024-47706");
  script_tag(name:"creation_date", value:"2024-12-12 04:32:26 +0000 (Thu, 12 Dec 2024)");
  script_version("2024-12-12T09:30:20+0000");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-03 16:47:24 +0000 (Thu, 03 Oct 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2938)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2938");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2938");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2938 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved:ntb: intel: Fix the NULL vs IS_ERR() bug for debugfs_create_dir() The debugfs_create_dir() function returns error pointers. It never returns NULL. So use IS_ERR() to check it.(CVE-2023-52917)

tracing: Free buffers when a used dynamic event is removed(CVE-2022-49006)

block, bfq: fix possible UAF for bfqq->bic with merge chain(CVE-2024-47706)

In the Linux kernel, the following vulnerability has been resolved:iommu: Return right value in iommu_sva_bind_device() iommu_sva_bind_device() should return either a sva bond handle or an ERR_PTR value in error cases. Existing drivers (idxd and uacce) only check the return value with IS_ERR(). This could potentially lead to a kernel NULL pointer dereference issue if the function returns NULL instead of an error pointer. In reality, this doesn't cause any problems because iommu_sva_bind_device() only returns NULL when the kernel is not configured with CONFIG_IOMMU_SVA. In this case, iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_SVA) will return an error, and the device drivers won't call iommu_sva_bind_device() at all.(CVE-2024-40945)

net: hns3: void array out of bound when loop tnl_num(CVE-2024-46833)

KVM: arm64: Make ICC_*SGI*_EL1 undef in the absence of a vGICv3(CVE-2024-46707)

net/mlx5: Fix bridge mode operations when there are no VFs(CVE-2024-46857)

In the Linux kernel, the following vulnerability has been resolved:netfilter: nft_socket: fix sk refcount leaks We must put 'sk' reference before returning.(CVE-2024-46855)

fsnotify: clear PARENT_WATCHED flags lazily(CVE-2024-47660)

tcp_bpf: fix return value of tcp_bpf_sendmsg()(CVE-2024-46783)

mlxsw: spectrum_acl_erp: Fix object nesting warning(CVE-2024-43880)

xdp: fix invalid wait context of page_pool_destroy()(CVE-2024-43834)

virtio_net: Fix napi_skb_cache_put warning (CVE-2024-43835)

net: hns3: fix kernel crash problem in concurrent scenario (CVE-2024-39507)

xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr()(CVE-2024-40959)

In the Linux kernel, the following vulnerability has been resolved:net: ena: Add validation for completion descriptors consistency Validate that `first` flag is set only for the first descriptor in multi-buffer packets. In case of an invalid descriptor, a reset will occur. A new reset reason for RX data corruption has been added.(CVE-2024-40999)

ipvlan: Dont Use skb->sk in ipvlan_process_v{4,6}_outbound(CVE-2024-33621)

net: relax socket state check at accept time(CVE-2024-36484)

net: fix information leakage in /proc/ net/ptype(CVE-2022-48757)

net: bridge: vlan: fix memory leak in __allowed_ingress(CVE-2022-48748)

In the Linux kernel, the following vulnerability has been resolved:USB: usbtmc: prevent kernel-usb-infoleak The syzbot reported a kernel-usb-infoleak in usbtmc_write, we need to clear the structure before filling fields.(CVE-2024-47671)

hv_netvsc: Register ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP12.");

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

if(release == "EULEROS-2.0SP12") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h2271.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h2271.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h2271.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h2271.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h2271.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h2271.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
