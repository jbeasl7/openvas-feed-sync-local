# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834595");
  script_version("2025-03-14T05:38:04+0000");
  script_cve_id("CVE-2025-24079", "CVE-2025-24078");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-14 05:38:04 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-11 17:16:31 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2025-03-12 06:16:37 +0000 (Wed, 12 Mar 2025)");
  script_name("Microsoft Word 2016 RCE Vulnerabilities (KB5002662)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002662");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to multiple remote code execution
  vulnerabilities in microsoft word.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution.");

  script_tag(name:"affected", value:"Microsoft Word 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002662");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");

exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer) {
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath) {
  exePath = "Unable to fetch the install path";
}

if(exeVer =~ "^16\." && version_is_less(version:exeVer, test_version:"16.0.5491.1000")) {
  report = report_fixed_ver(file_checked:exePath + "winword.exe", file_version:exeVer, vulnerable_range:"16.0 - 16.0.5491.0999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
