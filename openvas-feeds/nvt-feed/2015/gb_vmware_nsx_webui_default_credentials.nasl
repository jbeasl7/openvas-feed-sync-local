# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:vmware:nsx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105423");
  script_version("2022-12-13T10:10:56+0000");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"creation_date", value:"2015-10-27 16:29:45 +0100 (Tue, 27 Oct 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("VMware NSX Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_vmware_nsx_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("vmware/nsx/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote VMware NSX Web Management Interface is using default
  credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: admin/default");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

req = http_get(port: port, item: "/login.jsp");
res = http_keepalive_send_recv(port: port, data: req);

if (!cookie = http_get_cookie_from_header(buf: res))
  exit(0);

url = "/j_spring_security_check";

headers = make_array("Cookie", cookie,
                     "Content-Type", "application/x-www-form-urlencoded");

data = "j_username=admin&j_password=default&submit=";

req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

jsession = http_get_cookie_from_header(buf: res, pattern: "JSESSIONID=([^ ;\r\n]+)");
if (!jsession)
  exit(0);

xsrf_token = eregmatch(pattern: "XSRF-TOKEN=([^\r\n]+)", string: res);
if (isnull(xsrf_token[1]))
  exit(0);

cookie = "JSESSIONID=" + jsession + "; XSRF-TOKEN=" + xsrf_token[1];

if (http_vuln_check(port: port, url: "/index.html", pattern: "/manage/settings/general", cookie: cookie)) {
  report = 'It was possible to log in with the default username "admin" and password "default".';
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
