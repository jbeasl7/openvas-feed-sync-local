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

CPE = "cpe:/a:zen-cart:zen_cart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804179");
  script_version("2021-10-12T15:36:43+0000");
  script_tag(name:"last_modification", value:"2021-10-12 15:36:43 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2013-12-27 13:57:37 +0530 (Fri, 27 Dec 2013)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Zen Cart <= 1.5.1 Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zencart_http_detect.nasl");
  script_mandatory_keys("zen_cart/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Zen Cart is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to unspecified error that allows
  unauthenticated access to the database backup.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  sensitive database information by downloading the database backup.");

  script_tag(name:"affected", value:"Zen Cart version 1.5.1 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2013120167");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/zen-cart-database-backup-disclosure");

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

url = dir + "/zc_install/sql/mysql_zencart.sql";

if (http_vuln_check(port: port, url: url, pattern: "Zen Cart SQL Load", check_header: TRUE,
                    extra_check: make_list("customers_id", "admin_name"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
