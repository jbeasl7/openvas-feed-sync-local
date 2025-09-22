# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807860");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-3280", "CVE-2016-3283", "CVE-2016-3282");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-07-13 11:10:10 +0530 (Wed, 13 Jul 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Viewer Multiple RCE Vulnerabilities (3170008)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-088.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as Office software fails
  to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Word Viewer 2007.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115395");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91582");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91592");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91589");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115393");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-088");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/WordView/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

wordviewVer = get_kb_item("SMB/Office/WordView/Version");
wordviewPath = get_kb_item("SMB/Office/WordView/Install/Path");
if(!wordviewPath){
  wordviewPath = "Unable to fetch the install path";
}

if(wordviewVer)
{
  ##https://support.microsoft.com/en-us/kb/3115393
  if(version_in_range(version:wordviewVer, test_version:"11.0", test_version2:"11.0.8430"))
  {
    report = 'File checked:     ' + wordviewPath + "Wordview.exe" + '\n' +
             'File version:     ' + wordviewVer  + '\n' +
             'Vulnerable range: 11.0 - 11.0.8430 \n' ;
    security_message(data:report);
  }
}

##If wordview installed
if(wordviewVer)
{
  InsPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
            item:"CommonFilesDir");
  if(InsPath)
  {
    offPath = InsPath + "\Microsoft Shared\" + "Office11";
    exeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");
    if(exeVer && exeVer =~ "^11")
    {
      ##https://support.microsoft.com/en-us/kb/3115395
      if(version_in_range(version:exeVer, test_version:"11.0", test_version2:"11.0.8429"))
      {
        report = 'File checked:     ' + offPath + "\mso.dll" + '\n' +
                 'File version:     ' + exeVer  + '\n' +
                 'Vulnerable range: 11.0 - 11.0.8429\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
