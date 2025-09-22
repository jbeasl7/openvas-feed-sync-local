# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145523");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2021-03-08 07:17:21 +0000 (Mon, 08 Mar 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2021-22883", "CVE-2021-22884", "CVE-2021-23840");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 10.x < 10.24.0, 12.x < 12.21.0, 14.x < 14.16.0, 15.x < 15.10.0 Multiple Vulnerabilities - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - HTTP2 'unknownProtocol' causes Denial of Service by resource exhaustion. (CVE-2021-22883)

  - DNS rebinding in --inspect (CVE-2021-22884)

  - OpenSSL - Integer overflow in CipherUpdate (CVE-2021-23840)");

  script_tag(name:"affected", value:"Node.js 10.x < 10.24.0, 12.x < 12.21.0, 14.x < 14.16.0 and 15.x < 15.10.0.");

  script_tag(name:"solution", value:"Update to version 10.24.0, 12.21.0, 14.16.0, 15.10.0 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/february-2021-security-releases/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v10.24.0/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v12.21.0/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v14.16.0/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v15.10.0/");

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

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.23.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.24.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.20.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.21.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14.0", test_version2: "14.15.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.16.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "15.0", test_version2: "15.09.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "15.10.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
