# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE_PREFIX = "cpe:/o:vicon_industries:network_camera";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107336");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-08-02 14:06:43 +0200 (Thu, 02 Aug 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_cve_id("CVE-2018-14019");

  script_name("Vicon Industries Network Cameras Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_vicon_industries_network_camera_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("vicon_industries/network_camera/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Vicon Industries Network Cameras are using default credentials.");

  script_tag(name:"vuldetect", value:"Tries to login using the default credentials: 'root:system'.");

  script_tag(name:"affected", value:"All Vicon Industries Network Cameras.");

  script_tag(name:"solution", value:"Change the default password.");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );

if( ! infos = get_app_port_from_cpe_prefix( cpe: CPE_PREFIX, service: "www" ) )
  exit( 0 );

port = infos["port"];
CPE  = infos["cpe"];

if( ! get_app_location( cpe: CPE, port: port, nofork: TRUE ) )
  exit( 0 );

username = "root";
password = "system";

req = http_get_req( port: port, url: "/accessset.html", add_headers: make_array( "Authorization", "Basic " + base64( str: username + ":" + password ) ) );
buf = http_keepalive_send_recv( port: port, data: req );

if( buf =~ '(Security|access) Settings<\\/title>' || buf =~ '<td class="subtitle">Passwords' ||
    buf =~ '(class="input">|helpbold=")change general password' || buf =~ 'helpsub="Passwords"' ) {
  report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
