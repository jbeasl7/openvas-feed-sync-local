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

CPE = "cpe:/a:miniupnp_project:miniupnpd";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140805");
  script_version("2021-06-03T02:00:18+0000");
  script_tag(name:"last_modification", value:"2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-02-23 13:56:14 +0700 (Fri, 23 Feb 2018)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-30 20:29:00 +0000 (Thu, 30 May 2019)");

  script_cve_id("CVE-2017-1000494");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MiniUPnP <= 2.0 DoS Vulnerability (CVE-2017-1000494)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_miniupnp_detect_tcp.nasl", "gb_miniupnp_detect_udp.nasl");
  script_mandatory_keys("miniupnp/detected");

  script_tag(name:"summary", value:"Uninitialized stack variable vulnerability in NameValueParserEndElt
  (upnpreplyparse.c) in miniupnpd allows an attacker to cause Denial of Service (Segmentation fault and Memory
  Corruption) or possibly have unspecified other impact.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"MiniUPnP version 2.0 and prior.");

  script_tag(name:"solution", value:"Apply the provided patch.");

  script_xref(name:"URL", value:"https://github.com/miniupnp/miniupnp/issues/268");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less_equal(version: version, test_version: "2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply Patch");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);