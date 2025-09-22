# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1450");
  script_cve_id("CVE-2016-3713", "CVE-2016-8630", "CVE-2017-1000252", "CVE-2017-17741", "CVE-2017-2583", "CVE-2017-2584", "CVE-2017-5715", "CVE-2017-7518", "CVE-2018-10853", "CVE-2018-3639", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222");
  script_tag(name:"creation_date", value:"2020-01-23 11:47:36 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-05 20:40:45 +0000 (Tue, 05 Apr 2022)");

  script_name("Huawei EulerOS: Security Advisory for kvm (EulerOS-SA-2019-1450)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1450");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1450");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kvm' package(s) announced via the EulerOS-SA-2019-1450 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The msr_mtrr_valid function in arch/x86/kvm/mtrr.c in the Linux kernel before 4.6.1 supports MSR 0x2f8, which allows guest OS users to read or write to the kvm_arch_vcpu data structure, and consequently obtain sensitive information or cause a denial of service (system crash), via a crafted ioctl call.(CVE-2016-3713)

Linux kernel built with the Kernel-based Virtual Machine (CONFIG_KVM) support is vulnerable to a null pointer dereference flaw. It could occur on x86 platform, when emulating an undefined instruction. An attacker could use this flaw to crash the host kernel resulting in DoS.(CVE-2016-8630)

Linux kernel built with the Kernel-based Virtual Machine (CONFIG_KVM) support was vulnerable to an incorrect segment selector(SS) value error. The error could occur while loading values into the SS register in long mode. A user or process inside a guest could use this flaw to crash the guest, resulting in DoS or potentially escalate their privileges inside the guest.(CVE-2017-2583)

arch/x86/kvm/emulate.c in the Linux kernel through 4.9.3 allows local users to obtain sensitive information from kernel memory or cause a denial of service (use-after-free) via a crafted application that leverages instruction emulation for fxrstor, fxsave, sgdt, and sidt.(CVE-2017-2584)

A reachable assertion failure flaw was found in the Linux kernel built with KVM virtualisation(CONFIG_KVM) support with Virtual Function I/O feature (CONFIG_VFIO) enabled. This failure could occur if a malicious guest device sent a virtual interrupt (guest IRQ) with a larger (>1024) index value.(CVE-2017-1000252)

An industry-wide issue was found in the way many modern microprocessor designs have implemented speculative execution of instructions (a commonly used performance optimization). There are three primary variants of the issue which differ in the way the speculative execution can be exploited. Variant CVE-2017-5715 triggers the speculative execution by utilizing branch target injection. It relies on the presence of a precisely-defined instruction sequence in the privileged code as well as the fact that memory accesses may cause allocation into the microprocessor's data cache even for speculatively executed instructions that never actually commit (retire). As a result, an unprivileged attacker could use this flaw to cross the syscall and guest/host boundaries and read privileged memory by conducting targeted cache side-channel attacks.(CVE-2017-5715)

A flaw was found in the way the Linux KVM module processed the trap flag(TF) bit in EFLAGS during emulation of the syscall instruction, which leads to a debug exception(#DB) being raised in the guest stack. A user/process inside a guest could use this flaw to potentially escalate their privileges inside the guest. Linux guests are not affected by this.(CVE-2017-7518)

Linux kernel compiled with the KVM virtualization (CONFIG_KVM) support is vulnerable to an ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kvm' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"kvm", rpm:"kvm~4.4.11~30.011", rls:"EULEROSVIRT-3.0.1.0"))) {
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
