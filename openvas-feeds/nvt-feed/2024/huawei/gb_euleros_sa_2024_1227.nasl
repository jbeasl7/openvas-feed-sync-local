# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2024.1227");
  script_cve_id("CVE-2023-40547", "CVE-2023-40548", "CVE-2023-40549", "CVE-2023-40550", "CVE-2023-40551");
  script_tag(name:"creation_date", value:"2024-03-12 04:24:08 +0000 (Tue, 12 Mar 2024)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 19:25:40 +0000 (Thu, 08 Feb 2024)");

  script_name("Huawei EulerOS: Security Advisory for shim (EulerOS-SA-2024-1227)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2024-1227");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2024-1227");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'shim' package(s) announced via the EulerOS-SA-2024-1227 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A remote code execution vulnerability was found in Shim. The Shim boot support trusts attacker-controlled values when parsing an HTTP response. This flaw allows an attacker to craft a specific malicious HTTP request, leading to a completely controlled out-of-bounds write primitive and complete system compromise.(CVE-2023-40547)

A flaw was found in the MZ binary format in Shim. An out-of-bounds read may occur, leading to a crash or possible exposure of sensitive data during the system's boot phase.(CVE-2023-40551)

An out-of-bounds read flaw was found in Shim when it tried to validate the SBAT information. This issue may expose sensitive data during the system's boot phase.(CVE-2023-40550)

An out-of-bounds read flaw was found in Shim due to the lack of proper boundary verification during the load of a PE binary. This flaw allows an attacker to load a crafted PE binary, triggering the issue and crashing Shim, resulting in a denial of service.(CVE-2023-40549)

A buffer overflow was found in Shim in the 32-bit system. The overflow happens due to an addition operation involving a user-controlled value parsed from the PE binary being used by Shim. This value is further used for memory allocation operations, leading to a heap-based buffer overflow. This flaw causes memory corruption and can lead to a crash or data integrity issues during the boot phase.(CVE-2023-40548)");

  script_tag(name:"affected", value:"'shim' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"shim", rpm:"shim~15.4~2.h24.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shim-aa64-storage", rpm:"shim-aa64-storage~15.4~2.h24.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
