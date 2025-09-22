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

CPE = "cpe:/a:zabbix:zabbix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103812");
  script_version("2022-02-23T10:57:32+0000");
  script_tag(name:"last_modification", value:"2022-02-23 10:57:32 +0000 (Wed, 23 Feb 2022)");
  script_tag(name:"creation_date", value:"2013-10-15 14:09:10 +0200 (Tue, 15 Oct 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 17:39:00 +0000 (Mon, 16 Dec 2019)");

  script_cve_id("CVE-2013-5743");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zabbix Multiple SQL Injection Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zabbix_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zabbix/http/detected");

  script_tag(name:"summary", value:"Zabbix API and Frontend are prone to multiple SQL injection
  (SQLi) vulnerabilities.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"A remote attacker could send specially-crafted SQL statements
  to multiple API methods using multiple parameters, which could allow the attacker to view, add,
  modify or delete information in the back-end database.");

  script_tag(name:"affected", value:"ZABBIX prior to 1.8.18 and 2.x prior to 2.0.9.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
  for more information.");

  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-7091");

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

url = dir + "/httpmon.php?applications=2%27";

if( http_vuln_check( port:port, url:url, pattern:"Error in query", extra_check:"You have an error in your SQL syntax" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
