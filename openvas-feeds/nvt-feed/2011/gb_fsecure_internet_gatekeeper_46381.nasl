# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:f-secure:internet_gatekeeper";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103082");
  script_version("2022-04-12T08:46:17+0000");
  script_tag(name:"last_modification", value:"2022-04-12 08:46:17 +0000 (Tue, 12 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-02-21 13:57:38 +0100 (Mon, 21 Feb 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-0453");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("F-Secure Internet Gatekeeper Log File Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_fsecure_internet_gatekeeper_http_detect.nasl");
  script_require_ports("Services/www", 9012);
  script_mandatory_keys("fsecure/internet_gatekeeper/http/detected");

  script_tag(name:"summary", value:"F-Secure Internet Gatekeeper is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to gain access to sensitive
  information. Information obtained may lead to other attacks.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46381");
  script_xref(name:"URL", value:"http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2011-1.html");

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

url = dir + "/fsecure/log/fssp.log";

if (http_vuln_check(port:port, url:url, pattern:"F-Secure Security Platform",
                    extra_check:make_list("Database version:", "Starting ArchiveScanner engine"))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
