# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2272");
  script_cve_id("CVE-2020-27066", "CVE-2020-36694", "CVE-2021-0129", "CVE-2021-3923", "CVE-2022-4269", "CVE-2022-4662", "CVE-2022-47929", "CVE-2023-0047", "CVE-2023-0394", "CVE-2023-0458", "CVE-2023-0461", "CVE-2023-1073", "CVE-2023-1074", "CVE-2023-1076", "CVE-2023-1095", "CVE-2023-1206", "CVE-2023-1281", "CVE-2023-1582", "CVE-2023-1838", "CVE-2023-1855", "CVE-2023-2124", "CVE-2023-2176", "CVE-2023-2177", "CVE-2023-2194", "CVE-2023-2248", "CVE-2023-2269", "CVE-2023-23454", "CVE-2023-23455", "CVE-2023-2483", "CVE-2023-25775", "CVE-2023-26545", "CVE-2023-28466", "CVE-2023-28772", "CVE-2023-3090", "CVE-2023-3117", "CVE-2023-3141", "CVE-2023-31436", "CVE-2023-3161", "CVE-2023-32233", "CVE-2023-3268", "CVE-2023-33203", "CVE-2023-3390", "CVE-2023-34256", "CVE-2023-35001", "CVE-2023-35788", "CVE-2023-3609", "CVE-2023-3611", "CVE-2023-3772", "CVE-2023-3776", "CVE-2023-3812", "CVE-2023-4128", "CVE-2023-4194", "CVE-2023-42753", "CVE-2023-42754", "CVE-2023-4622", "CVE-2023-4623", "CVE-2023-4921");
  script_tag(name:"creation_date", value:"2024-08-22 04:43:34 +0000 (Thu, 22 Aug 2024)");
  script_version("2024-08-22T05:05:50+0000");
  script_tag(name:"last_modification", value:"2024-08-22 05:05:50 +0000 (Thu, 22 Aug 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-17 20:10:37 +0000 (Thu, 17 Aug 2023)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2272)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2272");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2272");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2272 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In xfrm6_tunnel_free_spi of net/ipv6/xfrm6_tunnel.c, there is a possible use after free due to improper locking. This could lead to local escalation of privilege with System execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-168043318(CVE-2020-27066)

Vulnerability Summary for CVE-2023-0047(CVE-2023-0047)

A flaw incorrect access control in the Linux kernel USB core subsystem was found in the way user attaches usb device. A local user could use this flaw to crash the system.(CVE-2022-4662)

atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition rather than valid classification results).(CVE-2023-23455)

cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition rather than valid classification results).(CVE-2023-23454)

In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control configuration that is set up with 'tc qdisc' and 'tc class' commands. This affects qdisc_graft in net/sched/sch_api.c.(CVE-2022-47929)

A NULL pointer dereference flaw was found in rawv6_push_pending_frames in net/ipv6/raw.c in the network subcomponent in the Linux kernel. This flaw causes the system to crash.(CVE-2023-0394)

A flaw was found in the Linux kernel's TUN/TAP functionality. This issue could allow a local user to bypass network filters and get unauthorized access to some resources.(CVE-2023-1076)

A double-free flaw was found in the Linux kernel when the MPLS implementation handled sysctl allocation failures. This issue could allow a local user to cause a denial of service or possibly execute arbitrary code.(CVE-2023-26545)

In nf_tables_updtable, if nf_tables_table_enable returns an error, nft_trans_destroy is called to free the transaction object. nft_trans_destroy() calls list_del(), but the transaction was never placed on a list -- the list head is all zeroes, this results in a NULL pointer dereference.(CVE-2023-1095)

A memory leak flaw was found in the Linux kernel's Stream Control Transmission Protocol. This issue may occur when a user starts a malicious networking service and someone connects to this service. This could allow a local user to starve resources, causing a denial of service.(CVE-2023-1074)

A use-after-free flaw was found in the Linux kernel's TLS protocol functionality in how a user installs a tls context (struct tls_context) on a connected TCP socket. This flaw allows a local user to crash or potentially escalate ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.36~vhulk1907.1.0.h1500", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.19.36~vhulk1907.1.0.h1500", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~4.19.36~vhulk1907.1.0.h1500", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.36~vhulk1907.1.0.h1500", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.36~vhulk1907.1.0.h1500", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~4.19.36~vhulk1907.1.0.h1500", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
