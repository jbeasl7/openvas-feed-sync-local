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

CPE = "cpe:/a:wiccle:wiccle_web_builder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801288");
  script_version("2021-07-06T11:41:19+0000");
  script_tag(name:"last_modification", value:"2021-07-06 11:41:19 +0000 (Tue, 06 Jul 2021)");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-3208");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Wiccle Web Builder 'post_text' XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wiccle_http_detect.nasl");
  script_mandatory_keys("wiccle/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Wiccle Web Builder is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  passed via the 'post_text' parameter in a site 'custom_search' action to 'index.php', that allows
  attackers to execute arbitrary HTML and script code on the web server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  web script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Wiccle Web Builder (WWB) Versions 1.00 and 1.0.1 are known to
  be affected. Other versions might be affected as well.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41191");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/61466");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.com/1008-exploits/wiccle-xss.txt");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

vt_strings = get_vt_strings();

url = dir + "/index.php?module=site&show=post_search&post_text=%3Cmarquee" +
      "%3E%3Cfont%20color=red%20size=15%3E" + vt_strings["lowercase"] + "%20Attack%3C/font" +
      "%3E%3C/marquee%3E";

if (http_vuln_check(port: port, url: url,
                    pattern: "<b><marquee><font color=red size=15>" + vt_strings["lowercase"] +
                             "</font></marquee>")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);