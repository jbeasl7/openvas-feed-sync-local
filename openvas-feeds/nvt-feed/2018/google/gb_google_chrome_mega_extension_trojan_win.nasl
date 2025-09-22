# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813789");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-09-10 12:21:10 +0530 (Mon, 10 Sep 2018)");
  script_name("Google Chrome MEGA Extension Trojan - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Malware");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl", "smb_reg_service_pack.nasl",
                      "lsc_options.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("GoogleChrome/Win/Ver", "SMB/WindowsVersion");
  script_exclude_keys("win/lsc/disable_wmi_search", "win/lsc/disable_win_cmd_exec");

  script_add_preference(name:"Run check", type:"checkbox", value:"no", id:1);

  script_xref(name:"URL", value:"https://thehackernews.com/2018/09/mega-file-upload-chrome-extension.html");

  script_tag(name:"summary", value:"Checks for a trojaned Google Chrome MEGA extension.

  Note: This script is not running by default as it needs to crawl the target host for the affected
  file which puts high load on the target during the scan. Please enable it separately within the
  scripts preference.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as a trojaned version of MEGA extension was
  available in google-chrome webstore for installation and update.");

  script_tag(name:"impact", value:"Upon installation or auto update to trojaned version, extension
  would exfiltrate credentials for sites including amazon.com, live.com, github.com, google.com (or
  webstore login), myetherwallet.com, mymonero.com, idex.market and HTTP POST requests to any other
  sites. Then it will send them to a server located in Ukraine.");

  script_tag(name:"affected", value:"MEGA extension version 3.39.4 for Google Chrome on Windows.");

  script_tag(name:"solution", value:"Update the MEGA extension to version 3.39.5 or later. Please
  see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  # Version information available under path to mega.html
  script_tag(name:"qod", value:"75");

  exit(0);
}

run_check = script_get_preference( "Run check", id:1 );
if( run_check && "no" >< run_check )
  exit( 0 );

include("smb_nt.inc");
include("version_func.inc");
include("list_array_func.inc");
include("powershell_func.inc");

if( wmi_is_file_search_disabled() || is_win_cmd_exec_disabled() )
  exit( 0 );

fileList = powershell_wmi_file_search_query( dir_path_like:"%google%chrome%extensions%", file_name:"mega", file_extension:"html" );

if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

report = "";  # nb: To make openvas-nasl-lint happy...

foreach filePath( fileList ) {
  info = eregmatch( pattern:"(.*(g|G)oogle.(c|C)hrome.*(e|E)xtensions.[A-za-z]+\\([0-9._]+)\\(M|m)ega\\html)\\mega.html", string:filePath );

  if( ! info[5] ) continue;

  version = info[5];
  path = info[1];

  if( version_is_equal( version:version, test_version:"3.39.4" ) ) {
    VULN = TRUE;
    report += report_fixed_ver( installed_version:version, install_path:path, fixed_version:"3.39.5" ) + '\n';
  }
}

if( VULN ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
