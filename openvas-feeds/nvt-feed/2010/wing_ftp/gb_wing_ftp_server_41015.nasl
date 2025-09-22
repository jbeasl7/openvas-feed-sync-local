# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wftpserver:wing_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100690");
  script_version("2023-12-20T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-12-20 05:05:58 +0000 (Wed, 20 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-06-23 13:22:49 +0200 (Wed, 23 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Wing FTP Server <= 3.1.2 'PORT' Command DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_wing_ftp_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("wing_ftp/server/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121201711/https://www.securityfocus.com/bid/41015/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/511905");
  script_xref(name:"URL", value:"http://blog.trendmicro.com/trend-micro-discovers-wing-ftp-server-port-command-dos-bug/");

  script_tag(name:"summary", value:"Wing FTP Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause the server to crash,
  resulting in a denial-of-service condition. Other attacks may also be possible.");

  script_tag(name:"affected", value:"Wing FTP Server version 3.1.2 is known to be affected. Other
  versions may also be affected.

  This issue is known to be exploitable in Windows environment. Other platforms may also be affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more details.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
