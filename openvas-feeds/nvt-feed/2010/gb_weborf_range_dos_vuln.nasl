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

CPE = "cpe:/a:salvo_tomaselli:weborf_http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801222");
  script_version("2021-10-13T14:51:56+0000");
  script_tag(name:"last_modification", value:"2021-10-13 14:51:56 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2010-2262");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Weborf < 0.12.1 Header DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_weborf_http_detect.nasl");
  script_mandatory_keys("weborf/detected");

  script_tag(name:"summary", value:"Weborf is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by an error when processing malicious HTTP
  headers. By sending a specially-crafted Range header, a remote attacker could exploit this
  vulnerability to cause the application to crash.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of
  service.");

  script_tag(name:"affected", value:"Weborf prior to version 0.12.1.");

  script_tag(name:"solution", value:"Update to version 0.12.1 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59135");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40051");
  script_xref(name:"URL", value:"http://galileo.dmi.unict.it/wiki/weborf/doku.php?id=news:released_0.12.1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "0.12.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.12.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
