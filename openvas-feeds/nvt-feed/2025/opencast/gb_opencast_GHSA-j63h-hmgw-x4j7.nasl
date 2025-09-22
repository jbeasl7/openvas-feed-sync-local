# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opencast:opencast";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.134011");
  script_version("2025-08-01T05:45:36+0000");
  script_tag(name:"last_modification", value:"2025-08-01 05:45:36 +0000 (Fri, 01 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-07-29 11:43:25 +0000 (Tue, 29 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_cve_id("CVE-2025-54380");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Opencast < 17.6 Information Disclosure Vulnerability (GHSA-j63h-hmgw-x4j7)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_opencast_detect.nasl");
  script_mandatory_keys("opencast/detected");

  script_tag(name:"summary", value:"Opencast is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Opencast would incorrectly send the hashed global system
  account credentials when attempting to fetch mediapackage elements included in a mediapackage XML
  file.");

  script_tag(name:"affected", value:"Opencast prior to version 17.6.");

  script_tag(name:"solution", value:"Update to version 17.6 or later.");

  script_xref(name:"URL", value:"https://github.com/opencast/opencast/security/advisories/GHSA-j63h-hmgw-x4j7");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "17.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
