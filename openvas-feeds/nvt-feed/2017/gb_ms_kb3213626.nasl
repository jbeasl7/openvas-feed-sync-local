# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811670");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8744");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-09-13 09:23:25 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Office 2010 Service Pack 2 Remote Code Execution Vulnerability (KB3213626)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3213626");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Microsoft Office software
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to use a specially crafted file to perform actions in the security context of
  the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3213626");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100748");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## MS Office
offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
if(!path){
  exit(0);
}

if(offVer =~ "^(14\.)")
{
  filePath = path + "\Microsoft Shared\GRPHFLT";

  fileVer = fetch_file_version(sysPath:filePath, file_name:"pictim32.flt");
  if(fileVer && fileVer =~ "^(2010\.)")
  {
    if(version_is_less(version:fileVer, test_version:"2010.1400.4740.1000"))
    {
      report = 'File checked:     ' + filePath + "\pictim32.flt" + '\n' +
               'File version:     ' + fileVer  + '\n' +
               'Vulnerable range: ' + "2010 - 2010.1400.4740.0999" + '\n' ;
      security_message(data:report);
    }
  }
}
exit(0);
