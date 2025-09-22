# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113231");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-07-17 16:09:00 +0200 (Tue, 17 Jul 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Milesight Network Cameras Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_milesight_camera_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("milesight/network_camera/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Milesight Network Cameras use the default credentials admin:ms1234.");

  script_tag(name:"vuldetect", value:"Tries to login using default credentials.");

  script_tag(name:"affected", value:"All Milesight Network Cameras.");

  script_tag(name:"solution", value:"Change the default password.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

CPE = "cpe:/h:milesight:network_camera";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! get_app_location( cpe: CPE, port: port, nofork: TRUE ) )
  exit( 0 );

username = "admin";
password = "ms1234";
password_hash = hexstr( MD5( password ) );

url = '/vb.htm?checkpassword=0:' + username + ':' + password_hash;

buf = http_get_cache( port: port, item: url );

if( buf =~ 'OK[ ]*checkpassword' ) {
  report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
