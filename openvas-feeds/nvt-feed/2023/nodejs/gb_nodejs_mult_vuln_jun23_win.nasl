# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149826");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2023-06-21 07:58:54 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 13:09:00 +0000 (Thu, 01 Jun 2023)");

  # CVE-2023-30585 only affects Windows
  script_cve_id("CVE-2023-0465", "CVE-2023-0466", "CVE-2023-1255", "CVE-2023-2650",
                "CVE-2023-32067", "CVE-2023-31147", "CVE-2023-31124", "CVE-2023-31130",
                "CVE-2023-30581", "CVE-2023-30584", "CVE-2023-30587", "CVE-2023-30582",
                "CVE-2023-30583", "CVE-2023-30585", "CVE-2023-30586", "CVE-2023-30588",
                "CVE-2023-30589", "CVE-2023-30590");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 16.x < 16.20.1, 18.x < 18.16.1, 20.x < 20.3.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Node.js version 16.x through 16.20.0, 18.x through 18.16.0 and
  20.x through 20.3.0.");

  script_tag(name:"solution", value:"Update to version 16.20.1, 18.16.1, 20.3.1 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/june-2023-security-releases");

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

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.20.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.20.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "18.0", test_version_up: "18.16.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "18.16.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "20.0", test_version_up: "20.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
