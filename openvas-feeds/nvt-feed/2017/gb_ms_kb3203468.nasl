# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811234");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-0243");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-20 13:27:00 +0000 (Thu, 20 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-07-13 13:05:25 +0530 (Thu, 13 Jul 2017)");
  script_name("Microsoft Office 2010 Service Pack 2 Remote Code Execution Vulnerability (KB3203468)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3203468");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in Microsoft
  Office software when it fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to perform actions in the security
  context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3203468");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99446");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## MS Office
officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                       item:"ProgramFilesDir");
if(!path){
  exit(0);
}

##For office 2010
if(officeVer =~ "^14\.")
{
  offPath = path + "\Microsoft Office\Office14\PROOF";

  offexeVer = fetch_file_version(sysPath:offPath, file_name:"MSSP3GL.DLL");

  ## If not, Get Version from different path
  if(!offexeVer)
  {
    commonpath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                                 item:"CommonFilesDir");
    if(!commonpath){
      exit(0);
    }
    offPath = commonpath + "\Microsoft Shared\PROOF";

    offexeVer = fetch_file_version(sysPath:offPath, file_name:"mssp3gl.dll");
  }

  if(offexeVer && version_is_less(version:offexeVer, test_version:"15.0.4569.1503"))
  {
    report = 'File checked:     ' + offPath + "\mssp3gl.dll" + '\n' +
             'File version:     ' + offexeVer  + '\n' +
             'Vulnerable range: ' + "Less than 15.0.4569.1503" + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
exit(0);
