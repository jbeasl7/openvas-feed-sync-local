# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:qnap:photo_station";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.155260");
  script_version("2025-09-02T09:15:41+0000");
  script_tag(name:"last_modification", value:"2025-09-02 09:15:41 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-09-02 02:46:21 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2024-12923");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP Photo Station XSS Vulnerability (QSA-25-24)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_photo_station_detect.nasl");
  script_mandatory_keys("qnap/nas/photostation/detected");

  script_tag(name:"summary", value:"QNAP Photo Station is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If a remote attacker gains access to a user account, they can
  then exploit the vulnerability to bypass security mechanisms or read application data.");

  script_tag(name:"affected", value:"QNAP Photo Station version 6.4.x.");

  script_tag(name:"solution", value:"Update to version 6.4.5 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-25-24");

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

if (version_in_range_exclusive(version: version, test_version_lo: "6.4", test_version_up: "6.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
