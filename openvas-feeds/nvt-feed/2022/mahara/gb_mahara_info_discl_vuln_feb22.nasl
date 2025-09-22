# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mahara:mahara";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.147633");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2022-02-14 06:15:34 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 17:46:00 +0000 (Wed, 23 Feb 2022)");

  script_cve_id("CVE-2022-24111");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara 21.4.x < 21.04.3, 21.10.x < 21.10.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mahara_http_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Portfolios created in groups that have not been shared with
  non-group members and portfolios created on the site and institution levels can be viewed without
  requiring a login if the URL to these portfolios is known.");

  script_tag(name:"affected", value:"Mahara version 21.04.x through 21.04.02 and 21.10.0.");

  script_tag(name:"solution", value:"Update to version 21.04.3, 21.10.1 or later.");

  script_xref(name:"URL", value:"https://mahara.org/interaction/forum/topic.php?id=8996");

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

if (version_in_range_exclusive(version: version, test_version_lo: "21.04.0", test_version_up: "21.04.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.04.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.10.0", test_version_up: "21.10.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "21.10.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
