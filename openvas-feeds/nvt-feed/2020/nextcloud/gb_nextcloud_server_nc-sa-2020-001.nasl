# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nextcloud:nextcloud_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143455");
  script_version("2025-02-25T13:24:30+0000");
  script_tag(name:"last_modification", value:"2025-02-25 13:24:30 +0000 (Tue, 25 Feb 2025)");
  script_tag(name:"creation_date", value:"2020-02-05 07:20:16 +0000 (Wed, 05 Feb 2020)");
  script_tag(name:"cvss_base", value:"3.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 16:13:00 +0000 (Tue, 24 Mar 2020)");

  script_cve_id("CVE-2019-15612");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Nextcloud Server < 13.0.11, < 14.0.7, < 15.0.3 2FA Sessions Vulnerability (NC-SA-2020-001)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_server_http_detect.nasl");
  script_mandatory_keys("nextcloud/server/detected");

  script_tag(name:"summary", value:"Nextcloud Server is prone to a vulnerability where 2FA sessions are not
  properly expired on a password change.");

  script_tag(name:"insight", value:"A bug in Nextcloud Server causes pending 2FA logins to not be correctly
  expired when the password of the user is reset.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Nextcloud server versions prior 13.0.11, prior 14.0.7 and prior 15.0.3.");

  script_tag(name:"solution", value:"Update to version 13.0.11, 14.0.7, 15.0.3 or later.");

  script_xref(name:"URL", value:"https://nextcloud.com/security/advisory/?id=NC-SA-2020-001");

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

if (version_is_less(version: version, test_version: "13.0.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.0.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14.0.0", test_version2: "14.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.0.7", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "15.0.0", test_version2: "15.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
