# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903328");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2013-3889", "CVE-2013-3895");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2013-10-09 17:36:47 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Office Services Remote Code Execution vulnerability (2885089)");

  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
  Bulletin MS13-084.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Flaw is due to improper sanitation of user supplied input via a specially
  crafted Excel file.");

  script_tag(name:"affected", value:"Excel Services on Microsoft SharePoint Server 2007/2010/2013,

  Word Automation Services on Microsoft SharePoint Server 2010/2013.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  cause a DoS (Denial of Service), and compromise a vulnerable system.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55131");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62829");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-084");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

## SharePoint Server 2007 (wosrv & coreserver)
if(shareVer =~ "^12\.")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\12.0\Bin\Xlsrv.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6683.5001"))
    {
      security_message(port:port, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}

## SharePoint Server 2010
if(shareVer =~ "^14\.")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\14.0\Bin\Xlsrv.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7108.4999"))
    {
      security_message(port:port, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }

  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\14.0\WebServices\WordServer\Core\WdsrvWorker.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"14.0", test_version2:"14.0.6112.4999"))
    {
      security_message(port:port, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}

## SharePoint Server 2013
if(shareVer =~ "^15\.")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\15.0\Bin\Xlsrv.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4535.1506"))
    {
      security_message(port:port, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }

  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\15.0\WebServices\ConversionServices\WdsrvWorker.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"15.0", test_version2:"15.0.4514.999"))
    {
      security_message(port:port, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}

exit(99);
