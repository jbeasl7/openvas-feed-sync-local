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

CPE = "cpe:/a:kodak:insite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801909");
  script_version("2022-11-10T10:12:04+0000");
  script_tag(name:"last_modification", value:"2022-11-10 10:12:04 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-1427");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Kodak InSite <= 6.0 Multiple XSS Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kodak_insite_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("kodak/insite/http/detected");

  script_tag(name:"summary", value:"Kodak InSite is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to input validation error in 'Language'
  parameter to Pages/login.aspx, 'HeaderWarning' parameter to Troubleshooting
  /DiagnosticReport.asp and 'User-Agent' header to troubleshooting/speedtest.asp, which allows
  remote attackers to inject arbitrary web script or HTML.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This may allow the attacker to steal cookie-based authentication credentials and to launch other
  attacks.");

  script_tag(name:"affected", value:"Kodak InSite version 6.0.x and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2011/Mar/73");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46762");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65941");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/516880");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/516880/100/0/threaded");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/Pages/login.aspx?SessionTimeout=False&Language=de%26rflp=True','" +
      "00000000-0000-0000-0000-000000000000');alert('XSS!-TEST'); return false; a('";

if (http_vuln_check(port: port, url: url, pattern: ");alert\('XSS!-TEST'\);", check_header: TRUE)) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
