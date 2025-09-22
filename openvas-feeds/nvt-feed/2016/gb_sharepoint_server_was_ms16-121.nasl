# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809705");
  script_version("2025-08-05T05:45:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-7193");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 14:27:52 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2016-10-12 11:59:58 +0530 (Wed, 12 Oct 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft SharePoint Server WAS Remote Code Execution Vulnerability (3194063)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-121");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as Office software fails to
  properly handle RTF files.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"- Microsoft SharePoint Server 2010 Service Pack 2 Word Automation Services

  - Microsoft SharePoint Server 2013 Service Pack 1 Word Automation Services");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3118377");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93372");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3118352");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-121");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_sharepoint_smb_login_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("microsoft/sharepoint/server/smb-login/detected");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(isnull(port = get_app_port(cpe:CPE, service:"smb-login")))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

shareVer = infos["version"];
path = infos["location"];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## SharePoint Server 2010
if(shareVer =~ "^14\.")
{
  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\14.0\WebServices\WordServer\Core\sword.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"14.0", test_version2:"14.0.7174.5000"))
    {
      report = 'File checked:     ' +  path + "\14.0\WebServices\WordServer\Core\sword.dll" + '\n' +
               'File version:     ' +  dllVer2  + '\n' +
               'Vulnerable range: ' +  "14.0 - 14.0.7174.5000" + '\n' ;
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

## SharePoint Server 2013
if(shareVer =~ "^15\.")
{
  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\15.0\WebServices\ConversionServices\sword.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"15.0", test_version2:"15.0.4867.1001"))
    {
      report = 'File checked:     ' +  path + "\15.0\WebServices\ConversionServices\sword.dll"+ '\n' +
               'File version:     ' +  dllVer2  + '\n' +
               'Vulnerable range: ' +  "15.0 - 15.0.4867.1001" + '\n' ;
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
