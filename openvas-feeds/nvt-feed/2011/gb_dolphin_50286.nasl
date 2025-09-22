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

CPE = "cpe:/a:boonex:dolphin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103306");
  script_version("2022-03-03T11:03:24+0000");
  script_tag(name:"last_modification", value:"2022-03-03 11:03:24 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"creation_date", value:"2011-10-20 15:15:44 +0200 (Thu, 20 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_active");

  script_name("Dolphin <= 6.0 SQLi Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolphin_http_detect.nasl");
  script_mandatory_keys("boonex/dolphin/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Boonex Dolphin is prone to an SQL injection (SQLi)
  vulnerability because the application fails to properly sanitize user-supplied input before using
  it in an SQL query.");

  script_tag(name:"impact", value:"A successful exploit may allow an attacker to compromise the
  application, access or modify data, or exploit vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Dolphin version 6.1 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50286");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520146");
  script_xref(name:"URL", value:"http://en.securitylab.ru/lab/PT-2011-14");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url =  dir + "/xml/get_list.php?dataType=ApplyChanges&iNumb=1&iIDcat=%27";

if (http_vuln_check(port: port, url: url, pattern: "You have an error in your SQL syntax")) {
  report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
}

exit(99);
