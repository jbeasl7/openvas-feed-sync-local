# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814516");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2018-11-29 12:56:10 +0530 (Thu, 29 Nov 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-06 17:54:00 +0000 (Tue, 06 Sep 2022)");

  script_cve_id("CVE-2018-12121", "CVE-2018-12122", "CVE-2018-12123");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js Multiple Vulnerabilities (Nov 2018) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");

  script_tag(name:"summary", value:"Node.js is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2018-12123: If a Node.js is using url.parse() to determine the URL hostname, that hostname
  can be spoofed by using a mixed case 'javascript:' protocol,

  - CVE-2018-12122: An attacker can cause a Denial of Service (DoS) by sending headers very slowly
  keeping HTTP or HTTPS connections and associated resources alive for a long period of time

  - CVE-2018-12121: Denial of Service with large HTTP headers: by using a combination of many
  requests with maximum sized headers (almost 80 KB per connection), and carefully timed completion
  of the headers, it is possible to cause the HTTP server to abort from heap allocation failure.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  denial of service and spoofing attacks.");

  script_tag(name:"affected", value:"Node.js version 6.x prior to 6.15.0, 8.x prior to 8.14.0,
  10.x prior to 10.14.0 and 11.x prior to 11.3.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 6.15.0, 8.14.0, 10.14.0, 11.3.0 or
  later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/november-2018-security-releases");

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

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.15.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.15.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "8.0", test_version_up: "8.14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.14.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0", test_version_up: "10.14.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.14.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0", test_version_up: "11.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
