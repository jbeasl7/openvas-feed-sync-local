# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:emby:emby.releases";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.125259");
  script_version("2025-07-25T15:43:57+0000");
  script_tag(name:"last_modification", value:"2025-07-25 15:43:57 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-24 12:28:43 +0000 (Thu, 24 Jul 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2025-46383");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Emby Server < 4.8.9 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_emby_server_http_detect.nasl");
  script_mandatory_keys("emby/media_server/detected");

  script_tag(name:"summary", value:"Emby Server is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Emby Server is prone to a stored XSS due to improper
  neutralization of input during web page generation.");

  script_tag(name:"affected", value:"Emby Server prior to version 4.8.9.");

  script_tag(name:"solution", value:"Update to version 4.8.9 or later.");

  script_xref(name:"URL", value:"https://www.gov.il/en/departments/dynamiccollectors/cve_advisories_listing?skip=0");

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

if (version_is_less(version: version, test_version: "4.8.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
