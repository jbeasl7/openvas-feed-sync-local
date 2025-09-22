# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807866");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2016-3279", "CVE-2016-3281", "CVE-2016-3282");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-07-13 15:52:42 +0530 (Wed, 13 Jul 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Web Apps Multiple Vulnerabilities (3170008)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-088.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Office software fails to properly handle objects in memory.

  - Office software improperly handles the parsing of file formats.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to bypass certain security restrictions and execute arbitrary code on
  affected system.");

  script_tag(name:"affected", value:"- Microsoft Office Web Apps 2010 Service Pack 2 and prior

  - Microsoft Office Web Apps Server 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115289");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91589");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91588");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91587");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115318");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-088");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Web/Apps/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
webappVer = infos["version"];
path = infos["location"];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## Microsoft Office Web Apps 2010
if(webappVer =~ "^14\..*")
{
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\ConversionService\Bin\Converter\sword.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7171.5001"))
    {
     report = 'File checked:     ' +  path + "14.0\WebServices\ConversionService\Bin\Converter\sword.dll" + '\n' +
              'File version:     ' + dllVer  + '\n' +
              'Vulnerable range: ' + "14.0 - 14.0.7171.5001" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

## Microsoft Office Web Apps 2013
if(webappVer =~ "^15\..*")
{
  path = path + "\PPTConversionService\bin\Converter\";

  dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4841.999"))
    {
      report = 'File checked:     ' +  path + "msoserver.dll" + '\n' +
              'File version:     ' +  dllVer  + '\n' +
              'Vulnerable range: ' +  "15.0 - 15.0.4841.999" + '\n' ;

      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
