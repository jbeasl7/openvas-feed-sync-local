# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836215");
  script_version("2025-05-15T05:40:37+0000");
  script_cve_id("CVE-2025-29977", "CVE-2025-29979", "CVE-2025-30375", "CVE-2025-30376",
                "CVE-2025-30379", "CVE-2025-30381", "CVE-2025-30383");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-05-15 05:40:37 +0000 (Thu, 15 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 17:16:00 +0000 (Tue, 13 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-14 11:03:17 +0530 (Wed, 14 May 2025)");
  script_name("Microsoft Excel 2016 Multiple Vulnerabilities (KB5002717)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002717");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct remote code execution.");

  script_tag(name:"affected", value:"Microsoft Excel 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002717");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Excel/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

excelVer = get_kb_item("SMB/Office/Excel/Version");
if(!excelVer) {
  exit(0);
}

excelPath = get_kb_item("SMB/Office/Excel/Install/Path");
if(!excelPath) {
  excelPath = "Unable to fetch the install path";
}

if(version_in_range(version:excelVer, test_version:"16.0", test_version2:"16.0.5500.999")) {
  report = report_fixed_ver(file_checked:excelPath + "Excel.exe", file_version:excelVer, vulnerable_range:"16.0 - 16.0.5500.999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
