# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office_live_meeting";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804598");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2014-1817", "CVE-2014-1818");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-06-11 15:48:21 +0530 (Wed, 11 Jun 2014)");
  script_name("Microsoft Live Meeting Remote Code Execution Vulnerability (2967487)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS14-036.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error within Unicode Scripts Processor.

  - An error within GDI+ when validating images.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code
  and compromise a user's system.");

  script_tag(name:"affected", value:"Microsoft Live Meeting 2007 Console.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2957503");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67904");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2957509");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-036");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_live_meeting_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/OfficeLiveMeeting/Ver");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

appPath = get_app_location(cpe:CPE, skip_port:TRUE);
if(!appPath ||  "Could not find the install location from registry" >< appPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:appPath, file_name:"Ogl.dll");
if(!dllVer){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"12.0.6700.5000"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
