# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/o:siemens:scalance_";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103723");
  script_version("2023-03-06T10:19:58+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-06 10:19:58 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-05-30 16:44:04 +0200 (Thu, 30 May 2013)");
  script_name("Siemens SCALANCE Default Credentials (HTTP)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_simatic_scalance_consolidation.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("siemens/simatic/scalance/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Siemens SCALANCE device is using known default
  credentials for the HTTP login.");

  script_tag(name:"vuldetect", value:"Tries to login using known default credentials.");

  script_tag(name:"insight", value:"It was possible to login as user 'admin' with password 'admin'.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or to modify the system configuration.");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("host_details.inc");

if(!infos = get_app_port_from_cpe_prefix(cpe:CPE_PREFIX, service:"www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if(!get_app_location(cpe:cpe, port:port, nofork:TRUE))
  exit(0);

url = "/";
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("nonceA" >!< buf)
  exit(0);

noncea = eregmatch(pattern:'<input type="hidden" name="nonceA" value="([^"]+)">', string:buf);
if(isnull(noncea[1]))
  exit(0);

cookie = eregmatch(pattern:'Set-Cookie: siemens_ad_session=([^;]+);', string:buf);
if(isnull(cookie[1]))
  exit(0);

co = cookie[1];

host = http_host_name(port:port);

na   = noncea[1];
user = "admin";
pass = "admin";

login = 'encoded=' + user + "%3A" + hexstr(MD5(user + ":" + pass + ":" + na));
login += '&nonceA=' + na;

len = strlen(login);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Accept-Encoding: identity\r\n",
             "Connection: close\r\n",
             "Referer: http://", host, "/\r\n",
             "Cookie: siemens_ad_session=", co, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", len, "\r\n",
             "\r\n",
             login);

res = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Login Successful" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);