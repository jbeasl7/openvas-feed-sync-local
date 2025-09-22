# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:intel:active_management_technology_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107191");
  script_version("2024-08-23T15:40:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 15:40:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2017-10-19 13:48:56 +0700 (Thu, 19 Oct 2017)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13080");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology WPA2 Key Reinstallation Vulnerabilities - KRACK (INTEL-SA-00101)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_intel_amt_http_detect.nasl");
  script_mandatory_keys("intel/amt/detected");

  script_tag(name:"summary", value:"WPA2 as used in Intel Active Management Technology is prone to
  multiple security weaknesses aka Key Reinstallation Attacks (KRACK)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Intel AMT firmware versions 2.5.x, 2.6, 4.x, 6.x, 7.x, 8.x,
  9.x, 10.x and 11.0-11.8.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00101.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "2.5", test_version_up: "8.1.72.3002")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.72.3002");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.0", test_version_up: "9.1.42.3002")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.42.3002");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.2", test_version_up: "9.5.61.3012")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.5.61.3012");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "10.0", test_version_up: "10.0.56.3002")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.0.56.3002");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "11.0", test_version_up: "11.8.50.3425")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.8.50.3425");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
