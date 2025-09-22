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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800628");
  script_version("2022-12-26T10:12:01+0000");
  script_tag(name:"last_modification", value:"2022-12-26 10:12:01 +0000 (Mon, 26 Dec 2022)");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1907");
  script_name("Claroline 'notfound.php' SQLi Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35019");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34883");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50404");
  script_xref(name:"URL", value:"http://gsasec.blogspot.com/2009/05/claroline-v1811-cross-site-scripting.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_claroline_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("claroline/detected");

  script_tag(name:"summary", value:"Claroline is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - an error in 'claroline/linker/notfound.php' which is not properly sanitising input data passed
  via the 'Referer' header, before being returned to the user.

  - an error in 'group/group.php' which is not properly sanitising input data passed to the 'sort'
  parameter, before being used in an SQL query.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying
  database.");

  script_tag(name:"affected", value:"Claroline versions 1.8.11 and prior.");

  script_tag(name:"solution", value:"Update to version 1.8.12 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port(default:80);

version = get_kb_item("www/"+ port + "/Claroline");
if(!version)
  exit(0);

if(!version = eregmatch(pattern:"^(.+) under (/.*)$", string:version))
  exit(0);

if(version_is_less_equal(version:version[1], test_version:"1.8.11")){
  report = report_fixed_ver(installed_version:version[1], vulnerable_range:"Less than or equal to 1.8.11");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
