# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814212");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-8479");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-12 14:50:00 +0000 (Wed, 12 Dec 2018)");
  script_tag(name:"creation_date", value:"2018-09-17 14:45:59 +0530 (Mon, 17 Sep 2018)");
  script_name("Azure IoT SDK Spoofing Vulnerability (Sep 2018) - Windows");

  script_tag(name:"summary", value:"Azure IoT Device C SDK library is prone to a spoofing
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in how the HTTP transport
  library validates certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to impersonate a
  server used during the provisioning process.");

  script_tag(name:"affected", value:"Azure IoT C SDK");

  script_tag(name:"solution", value:"Upgrade to Azure IoT C SDK 1.2.9 or later. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"75");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8479");
  script_xref(name:"URL", value:"https://github.com/Azure/azure-iot-sdk-c/");
  script_xref(name:"URL", value:"https://github.com/Azure/azure-iot-sdk-c/releases/tag/2018-09-11");

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
fileList = powershell_wmi_file_search_version_query( file_name:"Microsoft.Azure.IoTHub.IoTHubClient" );

if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    if( version_is_less( version:version[1], test_version:"1.2.9" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"1.2.9" ) + '\n';
    }
  }
}

if( VULN ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
