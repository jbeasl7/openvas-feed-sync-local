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

CPE = "cpe:/a:thekelleys:dnsmasq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112193");
  script_version("2021-07-01T11:00:40+0000");
  script_tag(name:"last_modification", value:"2021-07-01 11:00:40 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"creation_date", value:"2018-01-25 12:15:27 +0100 (Thu, 25 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:24:00 +0000 (Wed, 09 Oct 2019)");
  script_cve_id("CVE-2017-15107");
  script_name("Dnsmasq <= 2.78 DNSSEC Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_dnsmasq_consolidation.nasl");
  script_mandatory_keys("thekelleys/dnsmasq/detected");

  script_xref(name:"URL", value:"http://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2018q1/011896.html");
  script_xref(name:"URL", value:"http://thekelleys.org.uk/dnsmasq/CHANGELOG");

  script_tag(name:"summary", value:"Dnsmasq is prone to an improper DNSSEC validation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Wildcard synthesized NSEC records could be improperly
  interpreted to prove the non-existence of hostnames that actually exist.");

  script_tag(name:"affected", value:"Dnsmasq through 2.78.");

  script_tag(name:"solution", value:"Update to version 2.79 or later.");

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

if (version_is_less(version: version, test_version: "2.79")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.79", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);