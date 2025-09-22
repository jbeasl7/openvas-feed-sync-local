# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.128134");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"creation_date", value:"2025-05-23 04:05:15 +0000 (Fri, 23 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2025-23166");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js < 20.19.2, 21.x < 22.15.1, 23.x < 23.11.1, 24.x < 24.0.2 DoS Vulnerability - Mac OS X");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_nodejs_detect_macosx.nasl");
  script_mandatory_keys("Nodejs/MacOSX/Ver");

  script_tag(name:"summary", value:"Node.js is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The C++ method SignTraits::DeriveBits() may incorrectly call
  ThrowException() based on user-supplied inputs when executing in a background thread, crashing
  the Node.js process. Such cryptographic operations are commonly applied to untrusted inputs.
  Thus, this mechanism potentially allows an adversary to remotely crash a Node.js runtime.");

  script_tag(name:"affected", value:"Node.js prior to version 20.19.2, 21.x prior to 22.15.1,
  23.x prior to 23.11.1 and 24.x prior to 24.0.2.");

  script_tag(name:"solution", value:"Update to version 20.19.2, 22.15.1, 23.11.1, 24.0.2 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/may-2025-security-releases");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/updates-cve-for-end-of-life");

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


if (version_is_less(version: version, test_version: "20.19.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.19.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "21.0", test_version_up: "22.15.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "22.15.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "23.0", test_version_up: "23.11.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "23.11.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "24.0", test_version_up: "24.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "24.0.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
