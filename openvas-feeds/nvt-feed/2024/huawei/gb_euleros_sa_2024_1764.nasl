# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1764");
  script_cve_id("CVE-2021-33631", "CVE-2022-48619", "CVE-2023-51043", "CVE-2023-52340", "CVE-2023-52438", "CVE-2023-52527", "CVE-2023-6040", "CVE-2023-6121", "CVE-2023-6531", "CVE-2023-6606", "CVE-2023-6915", "CVE-2023-6931", "CVE-2023-7192", "CVE-2024-0193", "CVE-2024-0340", "CVE-2024-0565", "CVE-2024-0607", "CVE-2024-0639", "CVE-2024-0641", "CVE-2024-0841", "CVE-2024-1086");
  script_tag(name:"creation_date", value:"2024-05-30 15:11:32 +0000 (Thu, 30 May 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-05 20:41:24 +0000 (Mon, 05 Feb 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-1764)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1764");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1764");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-1764 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: ipv4, ipv6: Fix handling of transhdrlen in __ip{,6}_append_data() Including the transhdrlen in length is a problem when the packet is partially filled (e.g. something like send(MSG_MORE) happened previously) when appending to an IPv4 or IPv6 packet as we don't want to repeat the transport header or account for it twice. This can happen under some circumstances, such as splicing into an L2TP socket. The symptom observed is a warning in __ip6_append_data(): WARNING: CPU: 1 PID: 5042 at net/ipv6/ip6_output.c:1800 __ip6_append_data.isra.0+0x1be8/0x47f0 net/ipv6/ip6_output.c:1800 that occurs when MSG_SPLICE_PAGES is used to append more data to an already partially occupied skbuff. The warning occurs when 'copy' is larger than the amount of data in the message iterator. This is because the requested length includes the transport header length when it shouldn't. This can be triggered by, for example: sfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_L2TP), bind(sfd, ...), // ::1 connect(sfd, ...), // ::1 port 7 send(sfd, buffer, 4100, MSG_MORE), sendfile(sfd, dfd, NULL, 1024), Fix this by only adding transhdrlen into the length if the write queue is empty in l2tp_ip6_sendmsg(), analogously to how UDP does things. l2tp_ip_sendmsg() looks like it won't suffer from this problem as it builds the UDP packet itself.(CVE-2023-52527)

In the Linux kernel, the following vulnerability has been resolved: binder: fix use-after-free in shinker's callback The mmap read lock is used during the shrinker's callback, which means that using alloc->vma pointer isn't safe as it can race with munmap(). As of commit dd2283f2605e ('mm: mmap: zap pages with read mmap_sem in munmap') the mmap lock is downgraded after the vma has been isolated. I was able to reproduce this issue by manually adding some delays and triggering page reclaiming through the shrinker's debug sysfs. (CVE-2023-52438)

A flaw in the routing table size was found in the ICMPv6 handling of Packet Too Big . The size of the routing table is regulated by periodic garbage collection. However, with Packet Too Big Messages it is possible to exceed the routing table size and garbage collector threshold. A user located in the local network or with a high bandwidth connection can increase the CPU usage of the server that accepts IPV6 connections up to 95%.(CVE-2023-52340)

A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation.The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT.(CVE-2024-1086)

A null pointer dereference flaw was found in the hugetlbfs_fill_super function in the Linux kernel hugetlbfs (HugeTLB pages) ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP12(x86_64).");

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

if(release == "EULEROS-2.0SP12-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h1526.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h1526.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h1526.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h1526.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h1526.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h1526.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
