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

CPE = "cpe:/a:thekelleys:dnsmasq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812010");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-13704", "CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14493",
                "CVE-2017-14494", "CVE-2017-14496", "CVE-2017-14495");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-11 01:29:00 +0000 (Fri, 11 May 2018)");
  script_tag(name:"creation_date", value:"2017-10-04 16:39:44 +0530 (Wed, 04 Oct 2017)");
  script_name("Dnsmasq < 2.78 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_dnsmasq_consolidation.nasl");
  script_mandatory_keys("thekelleys/dnsmasq/detected");

  script_xref(name:"URL", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101085");

  script_tag(name:"summary", value:"Dnsmasq is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A regression error.

  - A heap overflow in DNS code.

  - A heap overflow in IPv6 router advertisement code.

  - A stack overflow in DHCPv6 code.

  - An information leak in DHCPv6, causing Dnsmasq to forward memory from
    outside the packet buffer to a DHCPv6 server when acting as a relay.

  - Invalid boundary checks in the 'add_pseudoheader' function allows a memcpy
    call with negative size.

  - An out-of-memory error.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a Denial of Service (DoS) condition, take control of affected system and gain
  access to potentially sensitive information.");

  script_tag(name:"affected", value:"Dnsmasq prior to 2.78.");

  script_tag(name:"solution", value:"Update to version 2.78 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.78")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.78", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);