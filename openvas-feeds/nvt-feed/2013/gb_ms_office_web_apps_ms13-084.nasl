# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903327");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2013-3889", "CVE-2013-3895");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"creation_date", value:"2013-10-09 17:04:48 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Office Web Apps Remote Code Execution vulnerability (2885089)");

  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
  Bulletin MS13-084.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Flaw is due to improper sanitation of user supplied input via a specially
  crafted Excel file.");

  script_tag(name:"affected", value:"- Microsoft Web Applications 2010 Service Pack 2 and prior

  - Microsoft Excel Web App 2010 Service Pack 1 and prior");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  cause a DoS (Denial of Service), and compromise a vulnerable system.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62829");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(webappVer =~ "^14\.")
{
  ## Microsoft Office Web Apps 2010
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\wordserver\core\msoserver.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7108.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }

  ## Microsoft Office Excel Web App 2010
  dllVer2 = fetch_file_version(sysPath:path, file_name:"\14.0\Bin\Xlsrv.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"14.0", test_version2:"14.0.7108.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

exit(99);
