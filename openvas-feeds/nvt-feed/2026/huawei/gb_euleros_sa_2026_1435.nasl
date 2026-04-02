# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1435");
  script_cve_id("CVE-2025-5914", "CVE-2025-5916", "CVE-2025-5917", "CVE-2025-5918", "CVE-2025-60753");
  script_tag(name:"creation_date", value:"2026-03-16 13:39:49 +0000 (Mon, 16 Mar 2026)");
  script_version("2026-03-17T05:57:27+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:27 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-07 16:15:50 +0000 (Wed, 07 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for libarchive (EulerOS-SA-2026-1435)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.12\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1435");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1435");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libarchive' package(s) announced via the EulerOS-SA-2026-1435 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in libarchive bsdtar before version 3.8.1 in function apply_substitution in file tar/subst.c when processing crafted -s substitution rules. This can cause unbounded memory allocation and lead to denial of service (Out-of-Memory crash).(CVE-2025-60753)

A vulnerability has been identified in the libarchive library. This flaw involves an 'off-by-one' miscalculation when handling prefixes and suffixes for file names. This can lead to a 1-byte write overflow. While seemingly small, such an overflow can corrupt adjacent memory, leading to unpredictable program behavior, crashes, or in specific circumstances, could be leveraged as a building block for more sophisticated exploitation.(CVE-2025-5917)

A vulnerability has been identified in the libarchive library, specifically within the archive_read_format_rar_seek_data() function. This flaw involves an integer overflow that can ultimately lead to a double-free condition. Exploiting a double-free vulnerability can result in memory corruption, enabling an attacker to execute arbitrary code or cause a denial-of-service condition.(CVE-2025-5914)

A vulnerability has been identified in the libarchive library. This flaw involves an integer overflow that can be triggered when processing a Web Archive (WARC) file that claims to have more than INT64_MAX - 4 content bytes. An attacker could craft a malicious WARC archive to induce this overflow, potentially leading to unpredictable program behavior, memory corruption, or a denial-of-service condition within applications that process such archives using libarchive.(CVE-2025-5916)

A vulnerability has been identified in the libarchive library. This flaw can be triggered when file streams are piped into bsdtar, potentially allowing for reading past the end of the file. This out-of-bounds read can lead to unintended consequences, including unpredictable program behavior, memory corruption, or a denial-of-service condition.(CVE-2025-5918)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Huawei EulerOS Virtualization release 2.12.1.");

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

if(release == "EULEROSVIRT-2.12.1") {

  if(!isnull(res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~3.5.2~5.h7.eulerosv2r12", rls:"EULEROSVIRT-2.12.1"))) {
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
