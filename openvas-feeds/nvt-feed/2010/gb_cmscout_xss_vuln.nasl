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

CPE = "cpe:/a:cmscout:cmscout";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800791");
  script_version("2021-11-23T01:39:52+0000");
  script_tag(name:"last_modification", value:"2021-11-23 01:39:52 +0000 (Tue, 23 Nov 2021)");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-2154");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("CMScout <= 2.09 XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_cmscout_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cmscout/http/detected");

  script_tag(name:"summary", value:"CMScout is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the 'search'
  module when processing the 'search' parameter in 'index.php' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  script code.");

  script_tag(name:"affected", value:"CMScout version 2.09 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58996");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12806/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1288");

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

filename = dir + "/index.php?page=search&menuid=5";
useragent = http_get_user_agent();
authVariables = "search=VT+XSS+Testing&content=1&Submit=Search";

host = http_host_name(port: port);

req = string("POST ", filename, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
             "Accept-Language: en-us,en;q=0.5\r\n",
             "Accept-Encoding: gzip,deflate\r\n",
             "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
             "Keep-Alive: 300\r\n",
             "Connection: keep-alive\r\n",
             "Referer: http://", host, filename, "\r\n",
             "Cookie: cmscout2=1f9f3e24745df5907a131c9acb41e5ef\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(authVariables), "\r\n\r\n",
             authVariables);
res = http_keepalive_send_recv(port: port, data: req);

if ("(VT XSS Testing)" >< res){
  report = http_report_vuln_url(port: port, url: filename);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
