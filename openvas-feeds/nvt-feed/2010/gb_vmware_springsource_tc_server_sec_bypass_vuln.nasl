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

CPE = "cpe:/a:vmware:tc_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902188");
  script_version("2022-12-13T10:10:56+0000");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-1454");
  script_name("VMware SpringSource tc Server 'JMX' Interface Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_vmware_springsource_tc_server_detect.nasl");
  script_mandatory_keys("vmware/tc_server/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39778");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40205");
  script_xref(name:"URL", value:"http://www.springsource.com/security/cve-2010-1454");

  script_tag(name:"summary", value:"VMware SpringSource tc Server is prone to a security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is cused due to error in,
  'com.springsource.tcserver.serviceability.rmi.JmxSocketListener', if the listener is configured to
  use an encrypted password then entering either the correct password or an empty string will allow
  authenticated access to the JMX interface.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain JMX
  interface access via a blank password.");

  script_tag(name:"affected", value:"VMware SpringSource tc Server Runtime 6.0.19 and 6.0.20 before
  6.0.20.D and 6.0.25.A before 6.0.25.A-SR01.");

  script_tag(name:"solution", value:"Update to version 6.0.20.D, 6.0.25.A-SR01 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_equal(version:version, test_version:"6.0.19") ||
   version_in_range(version:version, test_version:"6.0.20", test_version2:"6.0.20.C") ||
   version_in_range(version:version, test_version:"6.0.25", test_version2:"6.0.25.A.SR00")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"6.0.20.D/6.0.25.A-SR01", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
