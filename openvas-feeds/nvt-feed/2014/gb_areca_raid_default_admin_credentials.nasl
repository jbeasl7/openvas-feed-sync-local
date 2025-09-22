# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103921");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Areca Raid Storage Manager Default Admin Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-13 12:02:06 +0200 (Thu, 13 Mar 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("Raid_Console/banner");
  script_require_ports("Services/www", 80);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Areca Raid Storage Manager web interface is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

if( "401 Unauthorized" >!< banner || 'WWW-Authenticate: Digest realm="Raid Console"' >!< banner || "nonce" >!< banner ) exit( 0 );

nonce = eregmatch(pattern:'nonce="([^"]+)', string:banner);
if(isnull(nonce[1])) {
    exit(0);
}

nonce = nonce[1];
cnonce = rand();
qop = "auth";
nc = "00000001";

ha1 = hexstr(MD5("admin:Raid Console:0000"));
ha2 = hexstr(MD5("GET:/"));
response = hexstr(MD5(string(ha1,":",nonce,":",nc,":",cnonce,":",qop,":",ha2)));

host = http_host_name(port:port);

req = 'GET / HTTP/1.1\r\n' +
      'Host: ' +  host + '\r\n' +
      'Authorization: Digest username="admin", realm="Raid Console",' +
      'nonce="' + nonce + '", uri="/",' +
      'response="' + response + '", qop=' + qop  + ', nc=' + nc  + ',' +
      'cnonce="' + cnonce + '"\r\n' +
       '\r\n';
buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "^HTTP/1\.[01] 200" && "<title>Raid Storage Manager</title>" >< buf )
{
  report = 'It was possible to login using "admin" as username and "0000" as password.\n';
  security_message(port:port, data:report);
  exit(0);
}

exit( 99 );
