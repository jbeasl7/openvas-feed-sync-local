# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.2608");
  script_cve_id("CVE-2021-47473", "CVE-2022-48666", "CVE-2022-48689", "CVE-2022-48691", "CVE-2022-48703", "CVE-2023-28746", "CVE-2023-52652", "CVE-2023-52656", "CVE-2023-52676", "CVE-2023-52683", "CVE-2023-52686", "CVE-2023-52698", "CVE-2024-26646", "CVE-2024-26828", "CVE-2024-26830", "CVE-2024-26845", "CVE-2024-26857", "CVE-2024-26907", "CVE-2024-26923", "CVE-2024-26924", "CVE-2024-26925", "CVE-2024-26931", "CVE-2024-26934", "CVE-2024-26947", "CVE-2024-26958", "CVE-2024-26960", "CVE-2024-26973", "CVE-2024-26974", "CVE-2024-26976", "CVE-2024-26982", "CVE-2024-26984", "CVE-2024-26988", "CVE-2024-26993", "CVE-2024-27004", "CVE-2024-27008", "CVE-2024-27010", "CVE-2024-27011", "CVE-2024-27012", "CVE-2024-27013", "CVE-2024-27014", "CVE-2024-27019", "CVE-2024-27038", "CVE-2024-27043", "CVE-2024-27044", "CVE-2024-27046", "CVE-2024-27059", "CVE-2024-27073", "CVE-2024-27075", "CVE-2024-27389", "CVE-2024-27395", "CVE-2024-27431", "CVE-2024-35791", "CVE-2024-35807", "CVE-2024-35835", "CVE-2024-35847", "CVE-2024-36006", "CVE-2024-36008");
  script_tag(name:"creation_date", value:"2024-10-28 04:32:56 +0000 (Mon, 28 Oct 2024)");
  script_version("2025-01-09T06:16:22+0000");
  script_tag(name:"last_modification", value:"2025-01-09 06:16:22 +0000 (Thu, 09 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-30 17:41:16 +0000 (Mon, 30 Dec 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-2608)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-2608");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-2608");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-2608 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: scsi: qla2xxx: Fix a memory leak in an error path of qla2x00_process_els() Commit 8c0eb596baa5 ('[SCSI] qla2xxx: Fix a memory leak in an error path of qla2x00_process_els()'), intended to change: bsg_job->request->msgcode == FC_BSG_HST_ELS_NOLOGIN bsg_job->request->msgcode != FC_BSG_RPT_ELS but changed it to: bsg_job->request->msgcode == FC_BSG_RPT_ELS instead. Change the == to a != to avoid leaking the fcport structure or freeing unallocated memory.(CVE-2021-47473)

In the Linux kernel, the following vulnerability has been resolved: ACPI: LPIT: Avoid u32 multiplication overflow In lpit_update_residency() there is a possibility of overflow in multiplication, if tsc_khz is large enough (> UINT_MAX/1000). Change multiplication to mul_u32_u32(). Found by Linux Verification Center (linuxtesting.org) with SVACE.(CVE-2023-52683)

In the Linux kernel, the following vulnerability has been resolved: ipv4: check for NULL idev in ip_route_use_hint() syzbot was able to trigger a NULL deref in fib_validate_source() in an old tree [1]. It appears the bug exists in latest trees. All calls to __in_dev_get_rcu() must be checked for a NULL result. [1] general protection fault, probably for non-canonical address 0xdffffc0000000000: 0000 [#1] SMP KASAN KASAN: null-ptr-deref in range [0x0000000000000000-0x0000000000000007(CVE-2024-36008)

In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: clean up hook list when offload flags check fails splice back the hook list so nft_chain_release_hook() has a chance to release the hooks. (CVE-2022-48691)

In the Linux kernel, the following vulnerability has been resolved: calipso: fix memory leak in netlbl_calipso_add_pass() If IPv6 support is disabled at boot (ipv6.disable=1), the calipso_init() -> netlbl_calipso_ops_register() function isn't called, and the netlbl_calipso_ops_get() function always returns NULL. In this case, the netlbl_calipso_add_pass() function allocates memory for the doi_def variable but doesn't free it with the calipso_doi_free(). (CVE-2023-52698)

In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: fix a double-free in arfs_create_groups When `in` allocated by kvzalloc fails, arfs_create_groups will free ft->g and return an error. However, arfs_create_table, the only caller of arfs_create_groups, will hold this error and call to mlx5e_destroy_flow_table, in which the ft->g will be freed again.(CVE-2024-35835)

In the Linux kernel, the following vulnerability has been resolved: KVM: SVM: Flush pages under kvm->lock to fix UAF in svm_register_enc_region() Do the cache flush of converted pages in svm_register_enc_region() before dropping kvm->lock to fix use-after-free issues where region and/or its array of pages could be freed by a different task, e.g. if userspace has ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS Virtualization release 2.12.0.");

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

if(release == "EULEROSVIRT-2.12.0") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROSVIRT-2.12.0"))) {
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
