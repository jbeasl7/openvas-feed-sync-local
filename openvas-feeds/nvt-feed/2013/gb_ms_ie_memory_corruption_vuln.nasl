# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903213");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2013-3343");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2013-06-12 16:51:29 +0530 (Wed, 12 Jun 2013)");
  script_name("Microsoft Internet Explorer Memory Corruption Vulnerability (2755801)");

  script_tag(name:"summary", value:"This host is missing a security update according to Microsoft Security
  Advisory (2755801).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Unspecified flaw due to improper sanitization of user-supplied input.");

  script_tag(name:"affected", value:"- Microsoft Windows 8

  - Microsoft Windows 8.1

  - Microsoft Windows Server 2012");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  corrupt memory or cause a denial of service condition.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2847928");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60478");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2016/2755801");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8:1, win2012:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}
ieVer = get_app_version(cpe:CPE);

if(!ieVer || ieVer !~ "^1[01]\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

flashVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Macromed\Flash\Flash.ocx");
if(!flashVer){
  exit(0);
}
if(version_is_less(version:flashVer, test_version:"11.9.900.170"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
