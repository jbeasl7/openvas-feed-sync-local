# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143466");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2020-02-06 01:36:45 +0000 (Thu, 06 Feb 2020)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-16 01:15:00 +0000 (Sun, 16 Feb 2020)");

  script_cve_id("CVE-2020-8119");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 15.0.13, < 16.0.6, < 17.0.1 Information Disclosure Vulnerability (NC-SA-2019-012)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to an information disclosure vulnerability where
  file-drop content is visible through the gallery app.");

  script_tag(name:"insight", value:"Improper authorization causes leaking of previews and files when a file-drop
  share link is opened via the gallery app.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Nextcloud server versions prior 15.0.13, prior 16.0.6 and prior 17.0.1.");

  script_tag(name:"solution", value:"Update to version 15.0.13, 16.0.6, 17.0.1 or later.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2019-012");

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

if (version_is_less(version: version, test_version: "15.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.0.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "16.0.0", test_version2: "16.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.0.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "17.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "17.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
