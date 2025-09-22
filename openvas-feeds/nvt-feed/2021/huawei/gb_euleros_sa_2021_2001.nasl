# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2001");
  script_cve_id("CVE-2020-14372", "CVE-2020-25632", "CVE-2020-25647", "CVE-2020-27749", "CVE-2020-27779", "CVE-2021-20225", "CVE-2021-20233");
  script_tag(name:"creation_date", value:"2021-07-01 07:37:55 +0000 (Thu, 01 Jul 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-10 20:28:25 +0000 (Wed, 10 Mar 2021)");

  script_name("Huawei EulerOS: Security Advisory for grub2 (EulerOS-SA-2021-2001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2001");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-2001");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'grub2' package(s) announced via the EulerOS-SA-2021-2001 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in grub2 in versions prior to 2.06. Setparam_prefix() in the menu rendering code performs a length calculation on the assumption that expressing a quoted single quote will require 3 characters, while it actually requires 4 characters which allows an attacker to corrupt memory by one byte for each quote in the input. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2021-20233)

A flaw was found in grub2 in versions prior to 2.06. The option parser allows an attacker to write past the end of a heap-allocated buffer by calling certain commands with a large number of specific short forms of options. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2021-20225)

A flaw was found in grub2 in versions prior to 2.06. The rmmod implementation allows the unloading of a module used as a dependency without checking if any other dependent module is still loaded leading to a use-after-free scenario. This could allow arbitrary code to be executed or a bypass of Secure Boot protections. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-25632)

A flaw was found in grub2 in versions prior to 2.06, where it incorrectly enables the usage of the ACPI command when Secure Boot is enabled. This flaw allows an attacker with privileged access to craft a Secondary System Description Table (SSDT) containing code to overwrite the Linux kernel lockdown variable content directly into memory. The table is further loaded and executed by the kernel, defeating its Secure Boot lockdown and allowing the attacker to load unsigned code. The highest threat from this vulnerability is to data confidentiality and integrity, as well as system availability.(CVE-2020-14372)

A flaw was found in grub2 in versions prior to 2.06. During USB device initialization, descriptors are read with very little bounds checking and assumes the USB device is providing sane values. If properly exploited, an attacker could trigger memory corruption leading to arbitrary code execution allowing a bypass of the Secure Boot mechanism. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.(CVE-2020-25647)

A flaw was found in grub2 in versions prior to 2.06. Variable names present are expanded in the supplied command line into their corresponding variable contents, using a 1kB stack buffer for temporary storage, without sufficient bounds checking. If the function is called with a command line that references a variable with a sufficiently large payload, it is possible to overflow the stack buffer, corrupt the stack frame and control execution which could also circumvent Secure Boot protections. The highest threat from this vulnerability is to data ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'grub2' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"grub2-common", rpm:"grub2-common~2.02~62.h29.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64", rpm:"grub2-efi-aa64~2.02~62.h29.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64-cdboot", rpm:"grub2-efi-aa64-cdboot~2.02~62.h29.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-efi-aa64-modules", rpm:"grub2-efi-aa64-modules~2.02~62.h29.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools", rpm:"grub2-tools~2.02~62.h29.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-extra", rpm:"grub2-tools-extra~2.02~62.h29.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"grub2-tools-minimal", rpm:"grub2-tools-minimal~2.02~62.h29.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
