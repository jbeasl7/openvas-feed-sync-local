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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100446");
  script_version("2022-02-18T10:29:50+0000");
  script_tag(name:"last_modification", value:"2022-02-18 10:29:50 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-01-13 11:20:27 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2009-4495");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Yaws <= 1.85 Command Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Yaws/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"Yaws is prone to a command-injection vulnerability because it
  fails to adequately sanitize user-supplied input in logfiles.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary commands
  in a terminal.");

  script_tag(name:"affected", value:"Yaws version 1.85 and probably prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37716");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508830");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default: 80);

banner = http_get_remote_headers(port: port);
if(!banner || banner !~ "Server\s*:\s*Yaws/")
  exit(0);

version = eregmatch(pattern: "Server: Yaws/([0-9.]+)", string: banner);
if(isnull(version[1]))
  exit(0);

if(version_is_less_equal(version: version[1], test_version: "1.85")) {
  report = report_fixed_ver(installed_version: version[1], fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
