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

CPE = "cpe:/a:wiccle:wiccle_web_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802228");
  script_version("2022-03-29T15:48:03+0000");
  script_tag(name:"last_modification", value:"2022-03-29 15:48:03 +0000 (Tue, 29 Mar 2022)");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Wiccle Web Builder CMS and iWiccle CMS Community Builder Multiple XSS Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wiccle_http_detect.nasl");
  script_mandatory_keys("wiccle/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Wiccle Web Builder and iWiccle CMS Community Builder are prone
  to multiple cross-site scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied
  input passed via the 'member_city', 'post_name', 'post_text', 'post_tag', 'post_member_name',
  'member_username' and  'member_tags' parameters to 'index.php', that allows attackers to execute
  arbitrary HTML and script code on the web server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected application/site.");

  script_tag(name:"affected", value:"Wiccle Web Builder CMS version 1.0.1 and prior.
  iWiccle CMS Community Builder version 1.2.1.1 and prior.");

  script_tag(name:"solution", value:"Update to Wiccle Web Builder CMS version 1.1.0 or later,
  update to iWiccle CMS Community Builder version 1.3.0 or later.");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=130");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62726");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_Wiccle_Web_Builder_and_iWiccle_CMS_Community_Builder.txt");
  script_xref(name:"URL", value:"http://www.wiccle.com/news/backstage_news/iwiccle/post/iwiccle_cms_community_builder_130_releas");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/index.php?module=members&show=member_search&member_" +
      "username=<script>alert('XSS-Test')<%2Fscript>";

if (http_vuln_check(port: port, url: url, pattern: "><script>alert\('XSS-Test'\)</script>",
                    check_header:TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
