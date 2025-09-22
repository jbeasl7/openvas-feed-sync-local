# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807857");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-3280", "CVE-2016-3282", "CVE-2016-3284");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-07-13 10:15:16 +0530 (Wed, 13 Jul 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Compatibility Pack Multiple RCE Vulnerabilities (3170008)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-088.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as office software fails
  to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office Compatibility Pack Service Pack 3 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115309");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91582");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91594");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115308");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-088");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/ComptPack/Version", "SMB/Office/XLCnv/Version", "SMB/Office/WordCnv/Version");

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

cmpPckVer = get_kb_item("SMB/Office/ComptPack/Version");
if(cmpPckVer && cmpPckVer =~ "^12\.")
{
  xlcnvVer = get_kb_item("SMB/Office/XLCnv/Version");
  if(xlcnvVer)
  {
    offpath = path + "\Microsoft Office\Office12";
    sysVer = fetch_file_version(sysPath:offpath, file_name:"excelcnv.exe");
    if(sysVer && sysVer =~ "^12\.")
    {
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6750.4999"))
      {
        report = 'File checked:      ' + offpath + "\excelcnv.exe" + '\n' +
                 'File version:      ' + sysVer  + '\n' +
                 'Vulnerable range:  12.0 - 12.0.6750.4999' + '\n' ;
       security_message(data:report);
       exit(0);
      }
    }
  }
}

wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(wordcnvVer && wordcnvVer =~ "^12\.")
{
  offpath = path + "\Microsoft Office\Office12";
  sysVer = fetch_file_version(sysPath:offpath, file_name:"Wordcnv.dll");
  if(sysVer && sysVer =~ "^12\.")
  {
    if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6752.4999"))
    {
      report = 'File checked:      ' + offpath + "\Wordcnv.dll" + '\n' +
               'File version:      ' + sysVer  + '\n' +
               'Vulnerable range:  12.0 - 12.0.6752.4999' + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
