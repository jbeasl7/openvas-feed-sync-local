# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:graylog:graylog";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105756");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-06-10 13:18:59 +0200 (Fri, 10 Jun 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Graylog Default Credentials Vulnerability (REST API)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_graylog_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 12900);
  script_mandatory_keys("graylog/rest_api/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Graylog installation has default credentials set.");

  script_tag(name:"vuldetect", value:"Tries to login with default credentials admin:admin");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information
  that may lead to further attacks.");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

if( ! port = get_app_port( cpe:CPE, service:"rest_api" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

user = "admin";
pass = "admin";
host_noport = http_host_name( dont_add_port:TRUE );
http_hostname = http_host_name( port:port );

data = '{"username":"' + user + '","password":"' + pass + '","host":"' + host_noport + '"}';

url = "/system/sessions";
req = http_post_put_req( port:port, url:url, data:data, accept_header:"application/json",
                         add_headers:make_array( "Content-Type", "application/json",
                                                 "Origin", http_hostname ) );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 200" && '{"valid_until"' >< buf && '"session_id":' >< buf ) {
  report = 'It was possible to login using username "admin" and password "admin"';
  report += '\n\n' + http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
