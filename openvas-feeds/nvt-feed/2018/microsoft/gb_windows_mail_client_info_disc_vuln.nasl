# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813701");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-8305");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-08 12:06:00 +0000 (Sat, 08 Sep 2018)");
  script_tag(name:"creation_date", value:"2018-07-16 18:16:53 +0530 (Mon, 16 Jul 2018)");
  script_name("Microsoft Windows Mail Client Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Advisory for CVE-2018-8305.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to en rror how Windows Mail Client
  processes embedded URLs.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to potentially
  gain access to sensitive information.");

  script_tag(name:"affected", value:"Mail, Calendar, and People on Windows 8.1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8305");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  exit(0);
}

include("secpod_reg.inc");
include("smb_nt.inc");
include("version_func.inc");
include("powershell_func.inc");
include("list_array_func.inc");

if( wmi_is_file_search_disabled() || is_win_cmd_exec_disabled() )
  exit( 0 );

if( hotfix_check_sp( win8_1:1, win8_1x64:1 ) <= 0 )
  exit( 0 );

storelocation = registry_get_sz( key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx", item:"PackageRoot" );
if( ! storelocation )
  exit( 0 );

fileList = powershell_wmi_file_search_version_query( dir_path_like:"%microsoft%windowscommunicationsapps%", file_name:"microsoft.windowslive.platform", file_extension:"dll" );

if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach filePath( keys( fileList ) ) {

  if( tolower( storelocation ) >!< filePath || storelocation >!< filePath ) continue;

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    if( version_is_less( version:version[1], test_version:"17.5.9600.22013" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"17.5.9600.22013" ) + '\n';
    }
  }
}

if( VULN ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
