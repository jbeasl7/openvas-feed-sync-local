# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.810932");
  script_version("2023-02-22T10:19:34+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-02-22 10:19:34 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"creation_date", value:"2017-04-20 13:14:28 +0530 (Thu, 20 Apr 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Axis Network Cameras Multiple Vulnerabilities (Apr 2017)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_axis_devices_consolidation.nasl");
  script_mandatory_keys("axis/device/detected");

  script_tag(name:"summary", value:"Axis Network Cameras are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Axis software does not have any cross-site request forgery protection within the management
  interface.

  - No server-side security checks are present for Axis software.

  - Few Web service runs as root.

  - Lack of CSRF protection while using script editor function '/admin-bin/editcgi.cgi'.

  - Multiple root setuid .CGI scripts and binaries are present.

  - No option existed in Axis software to disable the HTTP interface. The web
    server will always listen on all network interfaces of the camera.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain root access to the device, execute arbitrary code and
  cause denial of service condition.");

  script_tag(name:"affected", value:"Axis Camera

  Model P1204, software versions <= 5.50.4

  Model P3225, software versions <= 6.30.1

  Model P3367, software versions <= 6.10.1.2

  Model M3045, software versions <= 6.15.4.1

  Model M3005, software versions <= 5.50.5.7

  Model M3007, software versions <= 6.30.1.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Mar/41");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:axis:p1204_firmware",
                     "cpe:/o:axis:p3225_firmware",
                     "cpe:/o:axis:p3367_firmware",
                     "cpe:/o:axis:m3045_firmware",
                     "cpe:/o:axis:m3005_firmware",
                     "cpe:/o:axis:m3007_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];
version = infos["version"];

if (cpe == "cpe:/o:axis:p1204_firmware") {
  if (version_is_less_equal(version: version, test_version: "5.50.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:axis:p3225_firmware") {
  if (version_is_less_equal(version: version, test_version: "6.30.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:axis:p3367_firmware") {
  if (version_is_less_equal(version: version, test_version: "6.10.1.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:axis:m3045_firmware") {
  if (version_is_less_equal(version: version, test_version: "6.15.4.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:axis:m3005_firmware") {
  if (version_is_less_equal(version: version, test_version: "5.50.5.7")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:axis:m3007_firmware") {
  if (version_is_less_equal(version: version, test_version: "6.30.1.1")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(0);
