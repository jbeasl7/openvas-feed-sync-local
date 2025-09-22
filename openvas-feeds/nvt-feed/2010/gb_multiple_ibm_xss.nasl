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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100538");
  script_version("2021-08-12T09:10:13+0000");
  script_tag(name:"last_modification", value:"2021-08-12 09:10:13 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"creation_date", value:"2010-03-17 13:20:23 +0100 (Wed, 17 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-0714");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Multiple IBM Products Login Page XSS Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38412");
  script_xref(name:"URL", value:"http://www.hacktics.com/#view=Resources%7CAdvisory");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21421469");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 10040);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Multiple IBM products are prone to a cross-site scripting (XSS)
  vulnerability because they fail to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected site. This may allow
  the attacker to steal cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"IBM Lotus Web Content Management, WebSphere Portal,
  and Lotus Quickr.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:10040);

url = "/wps/wcm/webinterface/login/login.jsp";

buf = http_get_cache(port:port, item:url);

if (!buf || buf !~ "^HTTP/1\.[01] 200")
  exit(0);

url += "?%22%3E%3Cscript%3Ealert(%27vt-xss-test%27)%3C/script%3E";

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req);

if (buf =~ "^HTTP/1\.[01] 200" && egrep(pattern: "<script>alert\('vt-xss-test'\)</script>", string: buf, icase: TRUE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);