# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2134");
  script_cve_id("CVE-2022-49557", "CVE-2022-49781", "CVE-2022-49784", "CVE-2022-49830", "CVE-2022-49870", "CVE-2022-49931", "CVE-2023-53039", "CVE-2023-53049", "CVE-2023-53065", "CVE-2023-53073", "CVE-2023-53084", "CVE-2023-53146", "CVE-2024-2201", "CVE-2024-58100", "CVE-2025-23149", "CVE-2025-37808", "CVE-2025-37911", "CVE-2025-37923", "CVE-2025-37927", "CVE-2025-37930", "CVE-2025-37948", "CVE-2025-37963", "CVE-2025-37995");
  script_tag(name:"creation_date", value:"2025-09-16 04:28:16 +0000 (Tue, 16 Sep 2025)");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-07 13:29:02 +0000 (Wed, 07 May 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2134)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2134");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2134");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2134 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"x86/fpu: KVM: Set the base guest FPU uABI size to sizeof(struct kvm_xsave).(CVE-2022-49557)

A cross-privilege Spectre v2 vulnerability allows attackers to bypass all deployed mitigations, including the recent Fine(IBT), and to leak arbitrary Linux kernel memory on Intel systems.(CVE-2024-2201)

perf/x86/amd/uncore: Fix memory leak for events array(CVE-2022-49784)

perf/x86/amd: Fix crash due to race between amd_pmu_enable_all, perf NMI and throttling(CVE-2022-49781)

perf/x86/amd/core: Always clear status for idx(CVE-2023-53073)

drm/drv: Fix potential memory leak in drm_dev_init().(CVE-2022-49830)

drm/shmem-helper: Remove another errant put in error path(CVE-2023-53084)

perf/core: Fix perf_output_begin parameter is incorrectly invoked in perf_event_bpf_output(CVE-2023-53065)

arm64: bpf: Only mitigate cBPF programs loaded by unprivileged users(CVE-2025-37963)

arm64: bpf: Add BHB mitigation to the epilogue for cBPF programs(CVE-2025-37948)

crypto: null - Use spin lock instead of mutex(CVE-2025-37808)

tracing: Fix oob write in trace_seq_to_buffer().(CVE-2025-37923)

media: dw2102: Fix null-ptr-deref in dw2102_i2c_transfer().(CVE-2023-53146)

usb: ucsi: Fix NULL pointer deref in ucsi_connector_change().(CVE-2023-53049)

iommu/amd: Fix potential buffer overflow in parse_ivrs_acpihid(CVE-2025-37927)

drm/nouveau: Fix WARN_ON in nouveau_fence_context_kill().(CVE-2025-37930)

module: ensure that kobject_put() is safe for module type kobjects(CVE-2025-37995)

bnxt_en: Fix out-of-bound memcpy() during ethtool -w(CVE-2025-37911)

capabilities: fix undefined behavior in bit shift for CAP_TO_MASK(CVE-2022-49870)

HID: intel-ish-hid: ipc: Fix potential use-after-free in work function(CVE-2023-53039)

IB/hfi1: Correctly move list in sc_disable().(CVE-2022-49931)

tpm: do not start chip while suspended(CVE-2025-23149)

bpf: check changes_pkt_data property for extension programs(CVE-2024-58100)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP13(x86_64).");

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

if(release == "EULEROS-2.0SP13-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~182.0.0.95.h2833.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~182.0.0.95.h2833.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~182.0.0.95.h2833.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~182.0.0.95.h2833.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~182.0.0.95.h2833.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~182.0.0.95.h2833.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
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
