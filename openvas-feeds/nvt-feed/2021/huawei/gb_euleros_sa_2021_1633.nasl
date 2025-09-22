# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1633");
  script_cve_id("CVE-2018-12182", "CVE-2019-11098", "CVE-2019-13224", "CVE-2019-13225", "CVE-2019-14553", "CVE-2019-14558", "CVE-2019-14559", "CVE-2019-14563", "CVE-2019-14575", "CVE-2019-14584", "CVE-2019-14586", "CVE-2019-14587", "CVE-2019-14588");
  script_tag(name:"creation_date", value:"2021-03-12 07:24:37 +0000 (Fri, 12 Mar 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-11 20:45:44 +0000 (Thu, 11 Jul 2019)");

  script_name("Huawei EulerOS: Security Advisory for edk2 (EulerOS-SA-2021-1633)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1633");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1633");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'edk2' package(s) announced via the EulerOS-SA-2021-1633 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"AuthenticodeVerify() calls OpenSSLs d2i_PKCS7() API to parse asn encoded signed authenticode pkcs#7 data. when this successfully returns, a type check is done by calling PKCS7_type_is_signed() and then Pkcs7->d.sign->contents->type is used. It is possible to construct an asn1 blob that successfully decodes and have d2i_PKCS7() return a valid pointer and have PKCS7_type_is_signed() also return success but have Pkcs7->d.sign be a NULL pointer.(CVE-2019-14584)

IA32_FEATURE_CONTROL stays unlocked in S3 after a warm reset(CVE-2019-14588)

We have found a TOCTOU vulnerability which allows an attacker with physical access to achieve code execution after the Boot Guard ACM computes and validates the hash of the IBB and measured the firmware into the TPM PCR0. This means the firmware will be marked as valid and have normal PCR0 values even though unsigned code has run. The root cause is when the FSP has finished memory init and disables MTRRs (and thereby the cache) in order to switch off No Evict Mode. The code doing this (the SecCore PeiTemporaryRamDonePpi callback), is executed directly from SPI flash, allowing an attacker to intercept execution flow. As a proof of concept we demonstrated that using an FPGA to substitute a single, targeted SPI transaction we can gain code execution.(CVE-2019-11098)

Insufficient control flow management in BIOS firmware for 8th, 9th, 10th Generation Intel(R) Core(TM), Intel(R) Celeron(R) Processor 4000 & 5000 Series Processors may allow an authenticated user to potentially enable denial of service via adjacent access.(CVE-2019-14558)

Logic issue EDK II may allow an unauthenticated user to potentially enable denial of service via adjacent access.(CVE-2019-14587)

Use after free vulnerability in EDK II may allow an authenticated user to potentially enable escalation of privilege, information disclosure and/or denial of service via adjacent access.(CVE-2019-14586)

A NULL Pointer Dereference in match_at() in regexec.c in Oniguruma 6.9.2 allows attackers to potentially cause denial of service by providing a crafted regular expression. Oniguruma issues often affect Ruby, as well as common optional libraries for PHP and Rust.(CVE-2019-13225)

A use-after-free in onig_new_deluxe() in regext.c in Oniguruma 6.9.2 allows attackers to potentially cause information disclosure, denial of service, or possibly code execution by providing a crafted regular expression. The attacker provides a pair of a regex pattern and a string, with a multi-byte encoding that gets handled by onig_new_deluxe(). Oniguruma issues often affect Ruby, as well as common optional libraries for PHP and Rust.(CVE-2019-13224)

Insufficient memory write check in SMM service for EDK II may allow an authenticated user to potentially enable escalation of privilege, information disclosure and/or denial of service via local access.(CVE-2018-12182)

Logic issue in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'edk2' package(s) on Huawei EulerOS Virtualization release 2.9.1.");

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

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"edk2-aarch64", rpm:"edk2-aarch64~201903~2.9.1.2.33", rls:"EULEROSVIRT-2.9.1"))) {
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
