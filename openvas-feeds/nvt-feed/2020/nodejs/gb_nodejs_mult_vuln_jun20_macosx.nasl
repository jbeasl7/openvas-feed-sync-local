# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112788");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-07-29 09:06:11 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2020-8174", "CVE-2020-11080");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 10.x < 10.21.0, 12.x < 12.18.0, 14.x < 14.4.0 Multiple Vulnerabilities - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - napi_get_value_string_*() allows various kinds of memory corruption (CVE-2020-8174)

  - HTTP/2 Large Settings Frame DoS (CVE-2020-11080)");

  script_tag(name:"affected", value:"Node.js 10.x < 10.21.0, 12.x < 12.18.0, and 14.x < 14.4.0.");

  script_tag(name:"solution", value:"Update to version 10.21.0, 12.18.0 or 14.4.0 respectively.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/june-2020-security-releases/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v10.21.0/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v12.18.0/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v14.4.0/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"10.0", test_version2:"10.20.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"10.21.0", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"12.0", test_version2:"12.17.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.18.0", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

if(version_in_range(version:vers, test_version:"14.0", test_version2:"14.3.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"14.4.0", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
