# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.836116");
  script_version("2025-04-11T15:45:04+0000");
  script_cve_id("CVE-2025-26642");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-08 18:15:48 +0000 (Tue, 08 Apr 2025)");
  script_tag(name:"creation_date", value:"2025-04-09 14:25:34 +0530 (Wed, 09 Apr 2025)");
  script_name("Microsoft Access 2016 RCE Vulnerability (KB5002701)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002701.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a remote code execution
  vulnerability in Microsoft Access.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to perform remote code execution.");

  script_tag(name:"affected", value:"Microsoft Access 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002701");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/Access/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");

vers = get_kb_item("SMB/Office/Access/Version");
if(!vers) {
  exit(0);
}

if(version_in_range(version:vers, test_version:"16.0", test_version2:"16.0.5493.0999")) {
  report = report_fixed_ver(file_checked:"msaccess.exe",
           file_version:vers, vulnerable_range:"16.0 - 16.0.5493.0999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);