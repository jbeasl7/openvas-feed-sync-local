# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902995");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-3155", "CVE-2013-3156", "CVE-2013-3157");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-09-11 10:26:41 +0530 (Wed, 11 Sep 2013)");
  script_name("Microsoft Office Access Database Remote Code Execution Vulnerabilities (2848637)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-074.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Multiple flaws are due to errors when processing ACCDB files.");

  script_tag(name:"affected", value:"- Microsoft Office 2013

  - Microsoft Office 2007 Service Pack 3 and prior

  - Microsoft Office 2010 Service Pack 2 and prior");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code via a specially crafted ACCDB file and compromise the system.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62229");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62230");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62231");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687425");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2810009");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-074");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_office_detection_900025.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver", "MS/Office/InstallPath");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007, 2010, 2013
if(!officeVer || officeVer !~ "^1[245]\."){
  exit(0);
}

InsPath = get_kb_item("MS/Office/InstallPath");
if(InsPath && "Could not find the install Location" >!< InsPath)
{
  foreach offsubver (make_list("Office12", "Office14", "Office15"))
  {
    exeVer = fetch_file_version(sysPath:InsPath + offsubver, file_name:"Acedao.dll");
    if(exeVer)
    {
      if(version_in_range(version:exeVer, test_version:"12", test_version2:"12.0.6650.4999") ||
         version_in_range(version:exeVer, test_version:"14", test_version2:"14.0.7010.999") ||
         version_in_range(version:exeVer, test_version:"15", test_version2:"15.0.4517.1002"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
