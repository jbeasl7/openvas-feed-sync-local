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

CPE = "cpe:/a:zen-cart:zen_cart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800820");
  script_version("2021-10-12T15:36:43+0000");
  script_tag(name:"last_modification", value:"2021-10-12 15:36:43 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-2254", "CVE-2009-2255");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zen Cart <= 1.3.8a Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_zencart_http_detect.nasl");
  script_mandatory_keys("zen_cart/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Zen Cart is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2009-2254: Error in admin/sqlpatch.php file due to lack of sanitisation of the input query
  string passed into the 'query_string' parameter in an execute action in conjunction with a
  PATH_INFO of password_forgotten.php file.

  - CVE-2009-2255: Access to admin/record_company.php is not restricted and can be exploited via
  the record_company_image parameter in conjunction with a PATH_INFO of password_forgotten.php,
  then accessing this file via a direct request to the file in images/.");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to execute
  SQL commands or arbitrary code by uploading a .php file, and compromise the application,
  or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Zen Cart version 1.3.8a and prior.");

  script_tag(name:"solution", value:"Apply the security patch from the references.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35550");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9004");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9005");
  script_xref(name:"URL", value:"http://www.zen-cart.com/forum/showthread.php?t=130161");
  script_xref(name:"URL", value:"http://www.zen-cart.com/forum/attachment.php?attachmentid=5965");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/admin/sqlpatch.php/password_forgotten.php?action=execute";

data = "query_string=;";

req = http_post(port: port, item: url, data: data);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ("1 statements processed" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
