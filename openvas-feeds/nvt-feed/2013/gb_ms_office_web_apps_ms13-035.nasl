# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902964");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-1289");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-04-10 11:55:11 +0530 (Wed, 10 Apr 2013)");
  script_name("Microsoft Office Web Apps HTML Sanitisation Component XSS Vulnerability (2821818)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2760777");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58883");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-035");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to bypass certain security
  restrictions and conduct cross-site scripting and spoofing attacks.");

  script_tag(name:"affected", value:"Microsoft Office Web Apps 2010 Service Pack 1.");

  script_tag(name:"insight", value:"Certain unspecified input is not properly sanitized within the HTML
  Sanitation component before being returned to the user. This can be
  exploited to execute arbitrary HTML and script code in a user's
  browser session in context of an affected site.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-035.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Microsoft Office Web Apps 2010 sp1
version = get_app_version(cpe:CPE);
if(!version){
  exit(0);
}

## Microsoft Office Web Apps 2010 sp1
if(version =~ "^14\..*")
{
  path = get_kb_item("MS/Office/Web/Apps/Path");
  if(path && "Could not find the install" >!< path )
  {
    path = path + "\14.0\WebServices\ConversionService\Bin\Converter";
    dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6134.4999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
