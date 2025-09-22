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

CPE = "cpe:/o:cisco:rv220w_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105792");
  script_version("2022-02-04T05:57:42+0000");
  script_tag(name:"last_modification", value:"2022-02-04 05:57:42 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2016-07-05 13:49:18 +0200 (Tue, 05 Jul 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:19:00 +0000 (Wed, 07 Dec 2016)");

  script_cve_id("CVE-2015-6319");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco RV220W Management Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_small_business_devices_consolidation.nasl");
  script_mandatory_keys("cisco/small_business/detected");

  script_tag(name:"summary", value:"A vulnerability in the web-based management interface of Cisco
  RV220W Wireless Network Security Firewall devices could allow an unauthenticated, remote attacker
  to bypass authentication and gain administrative privileges on a targeted device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient input validation of
  HTTP request headers that are sent to the web-based management interface of an affected device.
  An unauthenticated, remote attacker could exploit this vulnerability by sending a crafted HTTP
  request that contains malicious SQL statements to the management interface of a targeted device.
  Depending on whether remote management is configured for the device, the management interface may
  use the SQL code in the HTTP request header to determine user privileges for the device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to bypass
  authentication on the management interface and gain administrative privileges on the device.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160127-rv220");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

affected = make_list("1.0.0.2",
                     "1.0.0.30",
                     "1.0.1.9",
                     "1.0.2.6",
                     "1.0.3.10",
                     "1.0.4.10",
                     "1.0.4.14",
                     "1.0.5.4",
                     "1.0.5.6",
                     "1.0.5.8",
                     "1.0.6.6",
                     "1.1.0.9",
                     "1.2.0.2");

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
