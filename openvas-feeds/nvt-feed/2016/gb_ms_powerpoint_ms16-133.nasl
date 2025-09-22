# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809719");
  script_version("2023-09-22T16:08:59+0000");
  script_cve_id("CVE-2016-7230");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-09-22 16:08:59 +0000 (Fri, 22 Sep 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-11-09 13:16:52 +0530 (Wed, 09 Nov 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office PowerPoint Remote Code Execution Vulnerability (3199168)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-133.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as Office software fails to
  properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently logged-in
  user.");

  script_tag(name:"affected", value:"Microsoft PowerPoint 2010 Service Pack 2 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3118378");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94006");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-133");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PowerPnt/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

pptVer = get_kb_item("SMB/Office/PowerPnt/Version");
if(!pptVer){
  exit(0);
}

path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                       item:"ProgramFilesDir");
if(!path){
  exit(0);
}

# Office Power Point for 2010
offPath = path + "\Microsoft Office\OFFICE14";

exeVer = fetch_file_version(sysPath:offPath, file_name:"ppcore.dll");
if(exeVer && exeVer =~ "^14\..*")
{
  if(version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7176.4999"))
  {
    report = 'File checked:     ' + offPath + "\ppcore.dll"  + '\n' +
             'File version:     ' + exeVer  + '\n' +
             'Vulnerable range: ' + "14.0 - 14.0.7176.4999" + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
