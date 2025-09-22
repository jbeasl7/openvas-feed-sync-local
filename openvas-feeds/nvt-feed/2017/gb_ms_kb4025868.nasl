# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office_live_meeting";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811690");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2017-8676", "CVE-2017-8695", "CVE-2017-8696");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-21 18:47:00 +0000 (Thu, 21 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-13 16:16:50 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Live Meeting 2007 Console Multiple Vulnerabilities (KB4025868)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4025868");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The way that the Windows Graphics Device Interface (GDI) handles objects in
    memory, allowing an attacker to retrieve information from a targeted system.

  - When Windows Uniscribe improperly discloses the contents of its memory.

  - The way Windows Uniscribe handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to retrieve information from a targeted system. By itself, the information
  disclosure does not allow arbitrary code execution. However, it could allow
  arbitrary code to be run if the attacker uses it in combination with another
  vulnerability.");

  script_tag(name:"affected", value:"Microsoft Live Meeting 2007 Console.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025868");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100773");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100780");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_live_meeting_detect.nasl");
  script_mandatory_keys("MS/OfficeLiveMeeting/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

appPath = get_app_location(cpe:CPE, skip_port:TRUE);
if(!appPath ||  "Could not find the install location from registry" >< appPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:appPath, file_name:"Ogl.dll");
if(!dllVer){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"12.0.6776.5000"))
{
  report = 'File checked:     ' +  appPath + "Ogl.dll"+ '\n' +
           'File version:     ' +  dllVer  + '\n' +
           'Vulnerable range: Less than 12.0.6776.5000\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
