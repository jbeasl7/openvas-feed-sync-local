# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mahara:mahara";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.133054");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-08-27 08:35:34 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2024-35203");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara < 22.10.6, 23.04.6, 24.04.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mahara_http_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The server allows cross-site scripting (XSS) via a file, with
  JavaScript code as part of its name, that is uploaded via the Mahara filebrowser system.");

  script_tag(name:"affected", value:"Mahara versions prior to 22.10.6, version 23.04.6 and version
  24.04.1.");

  script_tag(name:"solution", value:"Update to version 22.10.6, 23.04.6, 24.04.1 or later.");

  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=9519");

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

if (version_is_less(version: version, test_version: "22.10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.10.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "23.04", test_version_up: "23.04.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.04.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "24.04", test_version_up: "24.04.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.04.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
