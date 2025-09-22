# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15622");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-1433");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3771");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3773");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Cherokee remote command execution");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Gain a shell remotely");
  script_dependencies("gb_cherokee_http_detect.nasl");
  script_mandatory_keys("cherokee/detected");

  script_tag(name:"solution", value:"Upgrade to Cherokee 0.2.7 or newer.");

  script_tag(name:"summary", value:"The remote version of Cherokee is vulnerable to remote
  command execution due to a lack of web requests sanitization, especially shell metacharacters.

  Additionally, this version fails to drop root privileges after it binds
  to listen port.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A remote attacker may submit a specially crafted web request to
  execute arbitrary command on the server with root privileges.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:cherokee-project:cherokee";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "0.2.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "0.2.7", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
