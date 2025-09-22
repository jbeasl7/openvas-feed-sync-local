# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:f5:big-iq_centralized_management";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105166");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-12 15:25:49 +0100 (Mon, 12 Jan 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("F5 Networks BIG-IQ Webinterface Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"Mitigation");

  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_f5_big_iq_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("f5/big_iq/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote F5 BIG-IQ web interface is using known default
  credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: admin/admin");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if ( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if ( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

pd = '{"username":"admin","password":"admin","needsToken":true}';

req = http_post( port:port, item:'/mgmt/shared/authn/login', data:pd );
res = http_keepalive_send_recv( port:port, data:req );

if( "Authentication failed" >!< res && ( "loginReference" >< res && "token" >< res && '"username":"admin"' >< res) ) {
  report = "It was possible to authenticate with the 'admin:admin' credentials.";
  security_message( port:port , data:report );
  exit( 0 );
}

exit( 99 );
