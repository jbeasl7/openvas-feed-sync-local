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

CPE_PREFIX = "cpe:/o:seagate:blackarmor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103754");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-08-08 14:02:06 +0200 (Thu, 08 Aug 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Seagate NAS Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_seagate_blackarmor_nas_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("seagate/blackarmor_nas/http/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Seagate NAS is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with admin/admin");

  script_tag(name:"insight", value:"It was possible to login with username 'admin' and password
  'admin'.");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("host_details.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe:CPE_PREFIX, service:"www"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if(!get_app_location(port:port, cpe:cpe, nofork:TRUE))
  exit(0);

url = "/index.php";
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Seagate NAS" >!< buf || "Set-Cookie" >!< buf)
  exit(0);

co = eregmatch(pattern:'Set-Cookie: ([^\n\r]+)', string:buf);
if(isnull(co[1]))
  exit(0);

cookie = co[1];

useragent = http_get_user_agent();
host = http_host_name(port:port);

data = "p_user=admin&p_pass=admin&lang=en&xx=1&loginnow=Login";
len = strlen(data);

req = 'POST / HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Referer: http://' + host + '/?lang=en\r\n' +
      'Cookie: ' + cookie + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' + data;
http_send_recv(port:port, data:req, bodyonly:FALSE);

req = 'GET /admin/system_status.php?lang=en&gi=sy002 HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Referer: http://' + host + '/?lang=en\r\n' +
      'Cookie: ' + cookie + '\r\n' + '\r\n';
buf = http_send_recv(port:port, data:req, bodyonly:TRUE);

if(">Logout<" >< buf && ">System Status<" >< buf && "Admin Password" >< buf) {
  security_message(port:port);
  exit(0);
}

exit(99);