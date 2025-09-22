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

CPE = "cpe:/a:hp:universal_cmbd_foundation";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106736");
  script_version("2024-07-26T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-07-26 05:05:35 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-04-10 12:58:34 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-25 13:58:42 +0000 (Thu, 25 Jul 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-5638");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP/HPE/Micro Focus Universal CMDB RCE Vulnerability (HPESBGN03733)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_microfocus_universal_cmdb_http_detect.nasl");
  script_mandatory_keys("hp_microfocus/ucmdb/detected");

  script_tag(name:"summary", value:"HP/HPE/Micro Focus Universal CMDB is prone to a remote code
  execution (RCE) vulnerability in Apache Struts.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A potential security vulnerability in Jakarta Multipart parser
  in Apache Struts has been addressed in HPE Universal CMDB. This vulnerability could be remotely
  exploited to allow code execution via mishandled file upload.");

  script_tag(name:"affected", value:"HP/HPE/Micro Focus Universal CMDB version v10.22 CUP5.");

  script_tag(name:"solution", value:"HPE has made mitigation information available to resolve the
  vulnerability for the impacted versions of HPE Universal CMDB.");

  script_xref(name:"URL", value:"https://support.microfocus.com/kb/kmdoc.php?id=KM02994289");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "10.22")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
