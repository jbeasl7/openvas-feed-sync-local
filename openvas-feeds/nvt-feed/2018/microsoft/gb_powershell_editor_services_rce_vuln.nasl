# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813676");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-8327");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 13:35:00 +0000 (Thu, 09 Sep 2021)");
  script_tag(name:"creation_date", value:"2018-07-17 14:49:04 +0530 (Tue, 17 Jul 2018)");
  script_name("Microsoft PowerShell Editor Services RCE Vulnerability");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft advisory (CVE-2018-8327).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper way of securing
  local connections by PowerShell Editor Services.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute malicious code on a vulnerable system.");

  script_tag(name:"affected", value:"PowerShell Editor Services 1.7.0 and below.");

  script_tag(name:"solution", value:"Upgrade PowerShell Editor Services to
  version 1.8.0 or later. Please see the references for more info.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8327");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104649");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShellEditorServices/issues/703");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("powershell_func.inc");
include("list_array_func.inc");

if( wmi_is_file_search_disabled() || is_win_cmd_exec_disabled() )
  exit( 0 );

# TODO: Limit to a possible known common path
fileList = powershell_wmi_file_search_version_query( file_name:"Microsoft.PowerShell.EditorServices", file_extension:"dll" );

if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

report = ""; # nb: To make openvas-nasl-lint happy...

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    if( version_is_less( version:version[1], test_version:"1.8.0" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"1.8.0" ) + '\n';
    }
  }
}

if( VULN ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
