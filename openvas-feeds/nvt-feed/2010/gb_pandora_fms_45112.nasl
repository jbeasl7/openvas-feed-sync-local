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

CPE = "cpe:/a:artica:pandora_fms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100927");
  script_version("2023-01-11T10:12:37+0000");
  script_tag(name:"last_modification", value:"2023-01-11 10:12:37 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"creation_date", value:"2010-12-01 14:30:53 +0100 (Wed, 01 Dec 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2010-4278", "CVE-2010-4279", "CVE-2010-4280", "CVE-2010-4281",
                "CVE-2010-4282", "CVE-2010-4283");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pandora FMS <= 3.1 Multiple Input Validation Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pandora_fms_http_detect.nasl");
  script_mandatory_keys("pandora_fms/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Pandora FMS is prone to an authentication bypass vulnerability
  as well as the following input-validation vulnerabilities:

  - A commandinjection vulnerability

  - Multiple SQL injection (SQLi) vulnerabilities

  - A remote file include (RFI) vulnerability

  - An arbitrary PHP code execution vulnerability

  - Multiple local file include (LFI) vulnerabilities");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Attackers may exploit these issues to execute local and remote
  script code in the context of the affected application, compromise the application, obtain
  sensitive information, access or modify data, exploit latent vulnerabilities in the underlying
  database, and gain administrative access to the affected application.");

  script_tag(name:"affected", value:"Pandora FMS version 3.1 and prior.");

  script_tag(name:"solution", value:"See the referenced advisories for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45112");
  script_xref(name:"URL", value:"http://pandorafms.org/index.php?sec=project&sec2=home&lng=en");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/514939");

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

url = dir + "/index.php?loginhash_data=21232f297a57a5a743894a0e4a801fc3&loginhash_user=admin&loginhash=1";

if (http_vuln_check(port:port, url:url,pattern:"This is your last activity in Pandora FMS console",
                    extra_check:make_list(":: Administration ::",":: Operation ::"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
