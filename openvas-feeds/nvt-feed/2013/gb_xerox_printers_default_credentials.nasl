# Copyright (C) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103649");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2013-01-30 15:51:27 +0100 (Wed, 30 Jan 2013)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Xerox Printer Default / No Credentials (HTTP)");

  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_xerox_printer_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xerox/printer/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Xerox Printer is using default or no credentials for
  the HTTP based interface.");

  script_tag(name:"vuldetect", value:"Checks if is possible to login to the remote HTTP based
  interface using default or no credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration without requiring authentication.");

  script_tag(name:"affected", value:"All Xerox printers using default or no credentials for the
  HTTP based interface.");

  script_tag(name:"solution", value:"Change the default password or enable authentication for the
  web interface.");

  script_xref(name:"URL", value:"http://www.h-online.com/security/news/item/Report-Thousands-of-embedded-systems-on-the-net-without-protection-1446441.html");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("xerox_printers.inc");

if( ! port = get_kb_item( "xerox/printer/http/port" ) )
  exit( 0 );

if( ! model = get_kb_item( "xerox/printer/http/" + port + "/model" ) )
  exit( 0 );

ret = check_xerox_default_login( model:model, port:port );

if( ret ) {
  if( ret == 1 ) {
    message = "It was possible to login into the remote Xerox " + model + ' printer with user "' +
              xerox_last_user + '" and password "' + xerox_last_pass + '"';
  }
  else if( ret == 2 ) {
    message = "The remote Xerox " + model + " printer is not protected by a username and password.";
  }

  security_message( port:port, data:message );
  exit( 0 );
}

exit( 99 );
