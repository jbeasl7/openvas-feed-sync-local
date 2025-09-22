# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/o:axis:m1033-w_firmware";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113151");
  script_version("2023-02-22T10:19:34+0000");
  script_tag(name:"last_modification", value:"2023-02-22 10:19:34 +0000 (Wed, 22 Feb 2023)");
  script_tag(name:"creation_date", value:"2018-04-06 13:37:37 +0200 (Fri, 06 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-15 15:35:00 +0000 (Tue, 15 May 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-9158");

  script_name("AXIS M1033-W IP Camera < 5.50.5.0 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_axis_devices_consolidation.nasl");
  script_mandatory_keys("axis/device/detected");

  script_tag(name:"summary", value:"AXIS M1033-W (IP camera) devices are prone to a denial of service
  (DoS) vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"AXIS M1033-W devices don't employ a suitable mechanism to prevent
  a DoS attack, which leads to a response time delay.");

  script_tag(name:"impact", value:"An attacker can use the hping3 tool to perform an IPv4 flood
  attack, and the services are interrupted from attack start to end.");

  script_tag(name:"affected", value:"M1033-W IP camera devices with firmware versions before
  5.50.5.0.");

  script_tag(name:"solution", value:"Update to firmware version 5.50.5.0 or above.");

  script_xref(name:"URL", value:"https://www.slideshare.net/secret/HpAEwK5qo5U4b1");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "5.50.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.50.5" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
