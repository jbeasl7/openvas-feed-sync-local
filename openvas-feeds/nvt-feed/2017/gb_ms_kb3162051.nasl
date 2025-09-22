# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811089");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8509");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-06-14 09:13:26 +0530 (Wed, 14 Jun 2017)");
  script_name("Microsoft Office Remote Code Execution Vulnerability (KB3162051)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3162051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98812");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3162051");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  the Microsoft Office software when the Office software fails to properly
  handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to use a specially crafted file and perform actions in the security context of
  the current user. The file could then, for example, take actions on behalf of
  the logged-on user with the same permissions as the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

offVer = get_kb_item("MS/Office/Ver");
if(!offVer || offVer !~ "^15\."){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!path){
  exit(0);
}

offPath = path + "\Microsoft Office\OFFICE15\DCF";

dllVer = fetch_file_version(sysPath:offPath, file_name:"Office.dll");
if(!dllVer){
  exit(0);
}

if(dllVer=~ "^15\.0" && version_is_less(version:dllVer, test_version:"15.0.4937.1000"))
{
  report = 'File checked:     ' + offPath + "\Office.dll" + '\n' +
           'File version:     ' + dllVer  + '\n' +
           'Vulnerable range:  15.0 - 15.0.4937.999'  + '\n' ;
  security_message(data:report);
  exit(0);
}
