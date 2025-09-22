# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nodejs:node.js";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148427");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2022-07-12 06:14:02 +0000 (Tue, 12 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-21 16:34:00 +0000 (Thu, 21 Jul 2022)");

  script_cve_id("CVE-2022-32223");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Node.js 14.x < 14.20.0, 16.x < 16.16.0 DLL Hijacking Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_nodejs_smb_login_detect.nasl");
  script_mandatory_keys("nodejs/smb-login/detected");

  script_tag(name:"summary", value:"Node.js is prone to a DLL hijacking vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability can be exploited if the victim has the
  following dependencies on Windows machine:

  - OpenSSL has been installed and 'C:\Program Files\Common Files\SSL\openssl.cnf' exists.

  Whenever the above conditions are present, node.exe will search for providers.dll in the current
  user directory. After that, node.exe will try to search for providers.dll by the DLL Search Order
  in Windows.

  It is possible for an attacker to place the malicious file providers.dll under a variety of paths
  and exploit this vulnerability.");

  script_tag(name:"affected", value:"Node.js version 14.x prior to 14.20.0 and 16.x prior to 16.16.0.");

  script_tag(name:"solution", value:"Update to version 14.20.0, 16.16.0 or later.");

  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/july-2022-security-releases/");

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

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.20.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.20.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "16.0", test_version_up: "16.16.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.16.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
