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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803199");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2013-05-14 17:25:01 +0530 (Tue, 14 May 2013)");
  script_name("ZyXEL ZyWALL Web Configurator Default Credentials (HTTP)");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2013/05/12/sunday-shodan-defaults/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RomPager/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"insight", value:"By default, ZyXEL ZyWALL installs with default user credentials
  (username/password combination). The web configurator account has a password of
  '1234', which is publicly known and documented. This allows remote attackers to
  trivially access the program or system and gain privileged access.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"summary", value:"ZyXEL ZyWALL Web Configurator is using known default credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain
  administrative access, circumventing existing authentication mechanisms.");

  script_tag(name:"affected", value:"ZyXEL ZyWALL");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if("Server: RomPager" >!< banner)
  exit(0);

url = "/Forms/rpAuth_1";

postData = "LoginPassword=ZyXEL+ZyWALL+Series&hiddenPassword=ee11cbb19052" +
           "e40b07aac0ca060c23ee&Prestige_Login=Login";

host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData);

res = http_keepalive_send_recv(port:port, data:req);
if(res =~ "^HTTP/1\.[01] 303" && res =~ "Location\s*:.*rpSys\.html") {
  security_message(port:port);
  exit(0);
}

exit(99);
