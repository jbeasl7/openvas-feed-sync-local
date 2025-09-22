# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodebb:nodebb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.133058");
  script_version("2025-09-03T08:26:15+0000");
  script_tag(name:"last_modification", value:"2025-09-03 08:26:15 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-08-29 08:03:16 +0000 (Fri, 29 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_cve_id("CVE-2025-50979");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NodeBB < 4.3.2 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_nodebb_http_detect.nasl");
  script_mandatory_keys("nodebb/detected");

  script_tag(name:"summary", value:"NodeBB is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The product is vulnerable to SQL injection in its
  search-categories API endpoint (/api/v3/search/categories). The search query parameter is not
  properly sanitized, allowing unauthenticated, remote attackers to inject boolean-based blind and
  PostgreSQL error-based payloads.");

  script_tag(name:"affected", value:"NodeBB versions prior to 4.3.2.");

  script_tag(name:"solution", value:"Update to version 4.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/NodeBB/NodeBB/releases/tag/v4.3.2");
  script_xref(name:"URL", value:"https://github.com/NodeBB/NodeBB/commit/16504bad8100aa25327dd8b8b26483df9e087b69");
  script_xref(name:"URL", value:"https://github.com/4rdr/proofs/blob/main/info/NodeBB-v4.3.0.-SQL-Injection-via-search-parameter.md");

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

if (version_is_less(version: version, test_version: "4.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
