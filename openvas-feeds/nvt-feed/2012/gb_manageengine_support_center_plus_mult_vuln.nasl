# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:zohocorp:manageengine_supportcenter_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802477");
  script_version("2022-12-21T10:12:09+0000");
  script_tag(name:"last_modification", value:"2022-12-21 10:12:09 +0000 (Wed, 21 Dec 2022)");
  script_tag(name:"creation_date", value:"2012-10-18 10:24:32 +0530 (Thu, 18 Oct 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Zoho ManageEngine Support Center Plus < 7.9.x Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_supportcenter_plus_http_detect.nasl");
  script_mandatory_keys("manageengine/supportcenter_plus/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"Zoho ManageEngine Support Center Plus is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - An improper checking of image extension when uploading the files. This will lead to uploading
  web site files which could be used for malicious actions.

  - An input passed to the 'fromCustomer' parameter via 'HomePage.do' script is not properly
  sanitised before being returned to the user.

  - An input passed to multiple parameters via 'WorkOrder.do' script is not properly sanitised
  before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to upload
  malicious code (backdoors/shells) or insert arbitrary HTML and script code, which will be
  executed in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"ManageEngine Support Center Plus 7.9 Upgrade Pack 7908 and
  prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22040/");
  script_xref(name:"URL", value:"http://www.bugsearch.net/en/13746/manageengine-support-center-plus-7908-multiple-vulnerabilities.html");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/HomePage.do?fromCustomer=%27;alert(document.cookie);%20var%20frompor=%27null";

if (http_vuln_check(port: port, url: url, pattern: "';alert\(document\.cookie\); var frompor='null",
                   check_header: TRUE, extra_check: ">ManageEngine SupportCenter Plus</")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
