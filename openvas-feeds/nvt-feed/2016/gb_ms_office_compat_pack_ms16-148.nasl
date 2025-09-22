# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809753");
  script_version("2023-07-21T05:05:22+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-7262", "CVE-2016-7264", "CVE-2016-7265", "CVE-2016-7266",
                "CVE-2016-7268", "CVE-2016-7290", "CVE-2016-7291");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:14:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-12-14 11:48:46 +0530 (Wed, 14 Dec 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Compatibility Pack Multiple Vulnerabilities (3204068)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-148.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Microsoft Office software reads out of bound memory.

  - Microsoft Office improperly handles input.

  - Microsoft Office improperly checks registry settings when an attempt is made
    to run embedded content.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information and run arbitrary
  code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office Compatibility Pack Service Pack 3 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3128024");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94721");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94662");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94672");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94670");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94671");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3128022");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms16-148");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/ComptPack/Version", "SMB/Office/XLCnv/Version");

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
  if(xlcnvVer && xlcnvVer =~ "^12\.")
  {
    offpath = path + "\Microsoft Office\Office12";
    sysVer = fetch_file_version(sysPath:offpath, file_name:"excelcnv.exe");
    if(sysVer && sysVer =~ "^12\.")
    {
      ## https://support.microsoft.com/en-us/kb/3128022
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6762.4999"))
      {
        report = 'File checked:      ' + offpath + "\excelcnv.exe" + '\n' +
                 'File version:      ' + sysVer  + '\n' +
                 'Vulnerable range:  12.0 - 12.0.6762.4999' + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }

  wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
  if(wordcnvVer && wordcnvVer =~ "^12\.")
  {
    offpath = path + "\Microsoft Office\Office12";
    {
      sysVer = fetch_file_version(sysPath:offpath, file_name:"Wordcnv.dll");
      if(sysVer && sysVer =~ "^12\.")
      {
        ## https://support.microsoft.com/en-us/kb/3128024
        if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6762.4999"))
        {
          report = 'File checked:      ' + offpath + "\Wordcnv.dll" + '\n' +
                   'File version:      ' + sysVer  + '\n' +
                   'Vulnerable range:  12.0 - 12.0.6762.4999' + '\n' ;
          security_message(data:report);
          exit(0);
        }
      }
    }
  }
}
