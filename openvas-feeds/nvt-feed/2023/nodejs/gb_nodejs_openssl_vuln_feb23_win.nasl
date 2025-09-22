# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149365");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2023-02-27 03:42:09 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 20:17:00 +0000 (Fri, 03 Mar 2023)");

  script_cve_id("CVE-2023-23919");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 16.x < 16.19.1, 18.x < 18.14.1, 19.x < 19.2.0 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");

  script_tag(name:"summary", value:"Node.js is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In some cases Node.js did does not clear the OpenSSL error
  stack after operations that may set it. This may lead to false positive errors during subsequent
  cryptographic operations that happen to be on the same thread. This in turn could be used to
  cause a denial of service.");

  script_tag(name:"affected", value:"Node.js version 16.x through 16.19.0, 18.x through 18.14.0 and
  19.x prior to 19.2.0.");

  script_tag(name:"solution", value:"Update to version 16.19.1, 18.14.1, 19.2.0 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/february-2023-security-releases/");

  exit(0);

}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.19.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.19.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "18.0", test_version_up: "18.14.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.14.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "19.0", test_version_up: "19.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.2.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
