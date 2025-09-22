# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811202");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-8513");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-21 13:44:00 +0000 (Wed, 21 Jun 2017)");
  script_tag(name:"creation_date", value:"2017-06-15 14:54:32 +0530 (Thu, 15 Jun 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Compatibility Pack RCE Vulnerability (KB3127894)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Update KB3127894.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as office software fails
  to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office Compatibility Pack Service Pack 3 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3127894");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98830");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/ComptPack/Version");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion", item:"ProgramFilesDir");
if(!path){
  exit(0);
}

## Path for 'Ppcnv.dll'
path = path +  "\Microsoft Office\Office12";
dllVer = fetch_file_version(sysPath:path, file_name:"Ppcnv.dll");
if(dllVer)
{
  if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6770.4999"))
  {
    report = 'File checked:      ' + path + "\Ppcnv.dll" + '\n' +
             'File version:      ' + dllVer  + '\n' +
             'Vulnerable range:  12.0 - 12.0.6770.4999' + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);
