# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834662");
  script_version("2024-10-11T05:05:54+0000");
  script_cve_id("CVE-2024-43504");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-11 05:05:54 +0000 (Fri, 11 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-08 18:15:12 +0000 (Tue, 08 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-09 16:00:11 +0530 (Wed, 09 Oct 2024)");
  script_name("Microsoft Excel 2016 RCE Vulnerability (KB5002643)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002643");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a remote code
  execution vulnerability in Microsoft Office.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution.");

  script_tag(name:"affected", value:"Microsoft Excel 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002643");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(version_in_range(version:excelVer, test_version:"16.0", test_version2:"16.0.5469.0999")) {
  report = report_fixed_ver(file_checked:excelPath + "Excel.exe", file_version:excelVer, vulnerable_range:"16.0 - 16.0.5469.0999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
