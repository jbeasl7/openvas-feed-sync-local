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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103543");
  script_version("2023-01-26T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-26 10:11:56 +0000 (Thu, 26 Jan 2023)");
  script_tag(name:"creation_date", value:"2012-08-19 12:46:01 +0200 (Sun, 19 Aug 2012)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Alpha Networks ADSL2/2+ Wireless Router ASL-26555 Information Disclosure Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Alpha Networks ADSL2/2+ ASL-26555 wireless router is prone to
  an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Successful exploits will allow unauthenticated attackers to
  obtain sensitive information of the device such as administrative password, which may aid in
  further attacks.");

  script_tag(name:"solution", value:"The only possible mitigation is to drop access to everyone
  from the outside with a network level blocking configuration.

  This can be done in the Advanced Configuration of the device.

  You can also turn off the web panel, but you won't be able to manage the device.");

  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/115663/Alpha-Networks-ADSL2-2-Wireless-Router-ASL-26555-Password-Disclosure.html");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8000);

res = http_get_cache(port: port, item: "/");

if ("<TITLE>ASL-26555" >!< res)
  exit(0);

url = "/APIS/returnJSON.htm";

if (http_vuln_check(port: port, url: url, pattern: '"USERNAME":',
                    extra_check: make_list('"PASSWORD":','"USER":','"RETURN":'))) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
