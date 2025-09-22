# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1859");
  script_cve_id("CVE-2021-46918", "CVE-2021-47036", "CVE-2021-47037", "CVE-2021-47070", "CVE-2021-47076", "CVE-2023-52433", "CVE-2023-52434", "CVE-2023-52435", "CVE-2023-52439", "CVE-2023-52443", "CVE-2023-52445", "CVE-2023-52447", "CVE-2023-52448", "CVE-2023-52451", "CVE-2023-52452", "CVE-2023-52454", "CVE-2023-52458", "CVE-2023-52462", "CVE-2023-52463", "CVE-2023-52464", "CVE-2023-52469", "CVE-2023-52474", "CVE-2023-52476", "CVE-2023-52477", "CVE-2023-52482", "CVE-2023-52484", "CVE-2023-52486", "CVE-2023-52504", "CVE-2023-52516", "CVE-2023-52522", "CVE-2023-52528", "CVE-2023-52530", "CVE-2023-52568", "CVE-2023-52572", "CVE-2023-52575", "CVE-2023-52578", "CVE-2023-52583", "CVE-2023-52587", "CVE-2023-52597", "CVE-2023-52598", "CVE-2023-52606", "CVE-2023-52615", "CVE-2023-52616", "CVE-2024-1151", "CVE-2024-23851", "CVE-2024-24855", "CVE-2024-26581", "CVE-2024-26583", "CVE-2024-26584", "CVE-2024-26585", "CVE-2024-26586", "CVE-2024-26589", "CVE-2024-26593", "CVE-2024-26595", "CVE-2024-26597", "CVE-2024-26598", "CVE-2024-26601", "CVE-2024-26602", "CVE-2024-26603", "CVE-2024-26606", "CVE-2024-26614", "CVE-2024-26625", "CVE-2024-26627");
  script_tag(name:"creation_date", value:"2024-07-01 04:14:03 +0000 (Mon, 01 Jul 2024)");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-15 14:21:29 +0000 (Fri, 15 Mar 2024)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2024-1859)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1859");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1859");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2024-1859 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In the Linux kernel, the following vulnerability has been resolved: crypto: lib/mpi - Fix unexpected pointer access in mpi_ec_init When the mpi_ec_ctx structure is initialized, some fields are not cleared, causing a crash when referencing the field when the structure was released. Initially, this issue was ignored because memory for mpi_ec_ctx is allocated with the __GFP_ZERO flag. For example, this error will be triggered when calculating the Za value for SM2 separately.(CVE-2023-52616)In the Linux kernel, the following vulnerability has been resolved: s390/ptrace: handle setting of fpc register correctly If the content of the floating point control (fpc) register of a traced process is modified with the ptrace interface the new value is tested for validity by temporarily loading it into the fpc register. This may lead to corruption of the fpc register of the tracing process: if an interrupt happens while the value is temporarily loaded into the fpc register, and within interrupt context floating point or vector registers are used, the current fp/vx registers are saved with save_fpu_regs() assuming they belong to user space and will be loaded into fp/vx registers when returning to user space. test_fp_ctl() restores the original user space fpc register value, however it will be discarded, when returning to user space. In result the tracer will incorrectly continue to run with the value that was supposed to be used for the traced process. Fix this by saving fpu register contents with save_fpu_regs() before using test_fp_ctl().(CVE-2023-52598)In the Linux kernel, the following vulnerability has been resolved: KVM: s390: fix setting of fpc register kvm_arch_vcpu_ioctl_set_fpu() allows to set the floating point control (fpc) register of a guest cpu. The new value is tested for validity by temporarily loading it into the fpc register. This may lead to corruption of the fpc register of the host process: if an interrupt happens while the value is temporarily loaded into the fpc register, and within interrupt context floating point or vector registers are used, the current fp/vx registers are saved with save_fpu_regs() assuming they belong to user space and will be loaded into fp/vx registers when returning to user space. test_fp_ctl() restores the original user space / host process fpc register value, however it will be discarded, when returning to user space. In result the host process will incorrectly continue to run with the value that was supposed to be used for a guest cpu. Fix this by simply removing the test. There is another test right before the SIE context is entered which will handles invalid values. This results in a change of behaviour: invalid values will now be accepted instead of that the ioctl fails with -EINVAL. This seems to be acceptable, given that this interface is most likely not used anymore, and this is in addition the same behaviour implemented with ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h1903.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
