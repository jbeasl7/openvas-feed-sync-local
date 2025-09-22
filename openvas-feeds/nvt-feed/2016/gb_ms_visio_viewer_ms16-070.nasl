# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807843");
  script_version("2024-07-25T05:05:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-3235");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 17:05:24 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2016-06-15 12:49:59 +0530 (Wed, 15 Jun 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Visio Viewer Remote Code Execution Vulnerability (3163610)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-070");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error within Office
  software when Windows improperly validates input before loading libraries.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and to
  perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Visio Viewer 2007 Service Pack 3

  - Microsoft Visio Viewer 2010");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2596915");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2999465");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3163610");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-070");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/VisioViewer/Ver");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


viewerPath = get_kb_item("SMB/Office/VisioViewer/Path");
if(!viewerPath){
  exit(0);
}

vvVer = fetch_file_version(sysPath:viewerPath, file_name:"VVIEWER.DLL");
if(!vvVer){
  exit(0);
}

## Visio Viewer 2007/2010
if(vvVer =~ "^(12|14)\..*")
{
  if(vvVer =~ "^12"){
    Vulnerable_range  =  "12 - 12.0.6676.4999";
  }
  else if(vvVer =~ "^14"){
    Vulnerable_range  =  "14 - 14.0.7163.4999";
  }

  if(version_in_range(version:vvVer, test_version:"14.0", test_version2:"14.0.7163.4999")||
     version_in_range(version:vvVer, test_version:"12.0", test_version2:"12.0.6676.4999"))
  {
    report = 'File checked:     ' + viewerPath + "\vviewer.dll" + '\n' +
             'File version:     ' + vvVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
