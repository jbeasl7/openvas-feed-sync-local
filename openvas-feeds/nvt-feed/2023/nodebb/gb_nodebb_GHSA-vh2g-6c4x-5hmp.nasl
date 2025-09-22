# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodebb:nodebb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126502");
  script_version("2025-01-30T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-01-30 05:38:01 +0000 (Thu, 30 Jan 2025)");
  script_tag(name:"creation_date", value:"2023-09-28 10:36:00 +0000 (Thu, 28 Sep 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 19:57:00 +0000 (Tue, 01 Aug 2023)");

  script_cve_id("CVE-2023-26045");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NodeBB 2.5.x < 2.8.7 Path Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_nodebb_http_detect.nasl");
  script_mandatory_keys("nodebb/detected");

  script_tag(name:"summary", value:"NodeBB is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to the use of the object destructuring assignment syntax
  in the user export code path, combined with a path traversal vulnerability, a specially crafted
  payload could invoke the user export logic to arbitrarily execute javascript files on the local
  disk.");

  script_tag(name:"affected", value:"NodeBB version 2.5.x prior to 2.8.7.");

  script_tag(name:"solution", value:"Update to version 2.8.7 or later.");

  script_xref(name:"URL", value:"https://github.com/NodeBB/NodeBB/security/advisories/GHSA-vh2g-6c4x-5hmp");

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

if (version_in_range_exclusive(version: version, test_version_lo: "2.5.0", test_version_up: "2.8.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
