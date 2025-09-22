# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146874");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2021-10-08 08:53:49 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-18 17:15:00 +0000 (Mon, 18 Oct 2021)");

  script_cve_id("CVE-2021-22930");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 12.x < 12.22.4, 14.x < 14.17.4, 16.x < 16.6.0 Use After Free Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");

  script_tag(name:"summary", value:"Node.js is prone to a use after free vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Node.js is vulnerable to a use after free attack where an
  attacker might be able to exploit the memory corruption, to change process behavior.");

  script_tag(name:"affected", value:"Node.js 12.x through 12.22.3, 14.x through 14.17.3 and 16.x
  prior to 16.6.0.");

  script_tag(name:"solution", value:"Update to version 12.22.4, 14.17.4, 16.6.0 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/july-2021-security-releases-2/");

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

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.22.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.22.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14.0", test_version2: "14.17.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.17.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version =~ "^16\." && version_is_less(version: version, test_version: "16.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.6.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
