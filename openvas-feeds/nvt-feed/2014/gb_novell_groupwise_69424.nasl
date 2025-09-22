# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:microfocus:groupwise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105078");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2014-09-03 15:23:42 +0200 (Wed, 03 Sep 2014)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2014-0600");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell Groupwise 2014 < 2014 SP1 File Access Vulnerability - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_microfocus_groupwise_consolidation.nasl");
  script_require_ports("Services/www", 9710);
  script_mandatory_keys("microfocus/groupwise/admin_console/detected");

  script_tag(name:"summary", value:"Novell Groupwise is prone to an arbitrary file access
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"FileUploadServlet in the Administration service allows remote
  attackers to read or write to arbitrary files via the poLibMaintenanceFileSave parameter.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to retrieve or delete
  arbitrary files, which may aid in further attacks.");

  script_tag(name:"affected", value:"Novell GroupWise 2014 prior to SP1.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69424");
  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=7015566");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"admin_console" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

vtstrings = get_vt_strings();
useragent = http_get_user_agent();
host = http_host_name(port:port);

test = '------------------------' + vtstrings["default"] + '\r\n' +
'Content-Disposition: form-data; name="poLibMaintenanceFileSave"\r\n' +
'\r\n' +
vtstrings["default"] + '_' + rand() + '_' + vtstrings["default"] + '\r\n' +
'------------------------' + vtstrings["default"] + '--';

len = strlen( test ) + 2;

req = 'POST /gwadmin-console/gwAdminConsole/fileUpload HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Accept: */*\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Connection: Close\r\n' +
      'Content-Type: multipart/form-data; boundary=----------------------' + vtstrings["default"] +'\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      test;
result = http_send_recv( port:port, data:req );

if( ! result || "login.jsp" >< result )
  exit( 99 );

if( "x-download" >< result && 'filename="gwcheck.opt"' >< result ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
