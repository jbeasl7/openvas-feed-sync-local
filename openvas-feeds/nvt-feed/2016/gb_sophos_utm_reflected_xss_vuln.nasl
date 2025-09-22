# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:sophos:unified_threat_management";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807074");
  script_version("2021-09-29T15:21:15+0000");
  script_tag(name:"last_modification", value:"2021-09-29 15:21:15 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"creation_date", value:"2016-02-18 10:58:19 +0530 (Thu, 18 Feb 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-06 20:03:00 +0000 (Tue, 06 Dec 2016)");

  script_cve_id("CVE-2016-2046");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sophos UTM 'lang' Parameter XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sophos_utm_http_detect.nasl");
  script_mandatory_keys("sophos/utm/http/detected");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"Sophos UTM is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation
  of user supplied input via the 'lang' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary script code in a user's browser session within the trust
  relationship between their browser and the server.");

  script_tag(name:"affected", value:"Sophos UTM version 9.350-12 with pattern
  version 92405 (potentially lower).");

  script_tag(name:"solution", value:"Update to version 9.353 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/135709");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Feb/60");
  script_xref(name:"URL", value:"http://www.halock.com/blog/cve-2016-2046-cross-site-scripting-sophos-utm-9");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/%3Flang%3Denglish%E2%80%9D%3Balert(document.cookie)%3B";

if (http_vuln_check(port: port, url: url, check_header: TRUE, pattern: "alert\(document.cookie\)")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
