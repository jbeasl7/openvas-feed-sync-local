# Copyright (C) 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111060");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Zebra PrintServer Default Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2015-11-25 11:00:00 +0100 (Wed, 25 Nov 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_default_credentials_options.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Zebra PrintServer Webinterface is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information.");

  script_tag(name:"vuldetect", value:"Try to login with a default password.");

  script_tag(name:"insight", value:"It was possible to login with default password 1234");

  script_tag(name:"solution", value:"Change the password.");

  script_xref(name:"URL", value:"https://support.zebra.com/cpws/docs/znet2/ps_firm/znt2_pwd.html");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

res = http_get_cache( item: "/settings", port:port );

if( "Zebra Technologies" >< res || "Internal Wired PrintServer" >< res || "ENTER PASSWORD" >< res) {

  vuln = 0;
  host = http_host_name( port:port );
  report = "";
  useragent = http_get_user_agent();
  data = string( "0=1234" );
  len = strlen( data );

  req = 'POST /authorize HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
        'Accept-Language: en-US,en;q=0.5\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;
  res = http_keepalive_send_recv( port:port, data:req );

  if( "Access Granted. This IP Address now has admin" >< res && "access to the restricted printer pages." >< res ) {
    security_message( port:port, data:'It was possible to login using the following password:\n\n1234' );
    exit( 0 );
  }
}

exit( 99 );
