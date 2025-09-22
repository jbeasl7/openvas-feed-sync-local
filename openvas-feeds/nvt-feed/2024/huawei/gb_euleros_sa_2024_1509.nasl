# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1509");
  script_cve_id("CVE-2021-33631", "CVE-2022-48619", "CVE-2023-51042", "CVE-2023-51043", "CVE-2023-52340", "CVE-2023-52435", "CVE-2023-52439", "CVE-2023-52448", "CVE-2023-6040", "CVE-2023-6121", "CVE-2023-6915", "CVE-2023-7192", "CVE-2024-0340", "CVE-2024-0565", "CVE-2024-0607", "CVE-2024-0639", "CVE-2024-1086", "CVE-2024-26585", "CVE-2024-26595");
  script_tag(name:"creation_date", value:"2024-04-08 07:57:56 +0000 (Mon, 08 Apr 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 20:41:24 +0000 (Mon, 05 Feb 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-1509)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP9\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1509");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1509");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-1509 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: tls: fix race between tx work scheduling and socket close Similarly to previous commit, the submitting thread (recvmsg/sendmsg) may exit as soon as the async crypto handler calls complete(). Reorder scheduling the work before calling complete(). This seems more logical in the first place, as it's the inverse order of what the submitting thread will do.(CVE-2024-26585)

In the Linux kernel, the following vulnerability has been resolved: mlxsw: spectrum_acl_tcam: Fix NULL pointer dereference in error path When calling mlxsw_sp_acl_tcam_region_destroy() from an error path after failing to attach the region to an ACL group, we hit a NULL pointer dereference upon 'region->group->tcam' [1]. Fix by retrieving the 'tcam' pointer using mlxsw_sp_acl_to_tcam(). (CVE-2024-26595)

In the Linux kernel, the following vulnerability has been resolved:gfs2: Fix kernel NULL pointer dereference in gfs2_rgrp_dump Syzkaller has reported a NULL pointer dereference when accessing rgd->rd_rgl in gfs2_rgrp_dump(). This can happen when creating
rgd->rd_gl fails in read_rindex_entry(). Add a NULL pointer check in gfs2_rgrp_dump() to prevent that.(CVE-2023-52448)

In the Linux kernel, the following vulnerability has been resolved: net: prevent mss overflow in skb_segment() Once again syzbot is able to crash the kernel in skb_segment() [1] GSO_BY_FRAGS is a forbidden value, but unfortunately the following computation in skb_segment() can reach it quite easily : mss = mss * partial_segs, 65535 = 3 * 5 * 17 * 257, so many initial values of mss can lead to a bad final result. Make sure to limit segmentation so that the new mss value is smaller than GSO_BY_FRAGS. (CVE-2023-52435)

In the Linux kernel, the following vulnerability has been resolved: uio: Fix use-after-free in uio_open core-1 core-2 ------------------------------------------------------- uio_unregister_device uio_open idev = idr_find() device_unregister(&idev->dev) put_device(&idev->dev) uio_device_release get_device(&idev->dev) kfree(idev) uio_free_minor(minor) uio_release put_device(&idev->dev) kfree(idev) ------------------------------------------------------- In the core-1 uio_unregister_device(), the device_unregister will kfree idev when the idev->dev kobject ref is 1. But after core-1 device_unregister, put_device and before doing kfree, the core-2 may get_device. Then: 1. After core-1 kfree idev, the core-2 will do use-after-free for idev. 2. When core-2 do uio_release and put_device, the idev will be double freed. To address this issue, we can get idev atomic & inc idev reference with minor_lock.(CVE-2023-52439)

A flaw in the routing table size was found in the ICMPv6 handling of Packet Too Big . The size of the routing table is regulated by periodic garbage collection. However, with Packet Too Big Messages it is possible to exceed the routing table size and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP9(x86_64).");

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

if(release == "EULEROS-2.0SP9-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.1.6.h1194.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.1.6.h1194.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.1.6.h1194.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.1.6.h1194.eulerosv2r9", rls:"EULEROS-2.0SP9-x86_64"))) {
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
