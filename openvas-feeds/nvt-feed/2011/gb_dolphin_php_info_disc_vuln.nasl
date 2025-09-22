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
  script_oid("1.3.6.1.4.1.25623.1.0.902735");
  script_version("2022-03-03T11:03:24+0000");
  script_tag(name:"last_modification", value:"2022-03-03 11:03:24 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-3728");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Dolphin <= 7.0.4 Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolphin_http_detect.nasl");
  script_mandatory_keys("boonex/dolphin/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Dolphin is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to error in certain '.php' files. A direct
  request to these files reveals the installation path in an error message.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain sensitive
  information.");

  script_tag(name:"affected", value:"Dolphin version 7.0.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://code.google.com/p/inspathx/source/browse/trunk/paths_vuln/Dolphin-7.0.4");

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

url = dir + "/xmlrpc/BxDolXMLRPCProfileView.php";

if (http_vuln_check(port: port, url: url, pattern: "<b>Fatal error</b>:  " +
                    "require_once\(\) \[<a href='function\.require'>function\.require</a>\]:" +
                    " Failed opening required.*xmlrpc/BxDolXMLRPCProfileView\.php")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
