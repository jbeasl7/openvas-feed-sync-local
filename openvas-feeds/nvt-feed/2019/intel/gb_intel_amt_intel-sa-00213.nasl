# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:intel:active_management_technology_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142466");
  script_version("2024-08-23T15:40:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 15:40:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2019-05-27 07:20:26 +0000 (Mon, 27 May 2019)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-22 15:38:00 +0000 (Mon, 22 May 2023)");

  script_cve_id("CVE-2019-0092", "CVE-2019-0094", "CVE-2019-0096", "CVE-2019-0097");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology Multiple Vulnerabilities (INTEL-SA-00213)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_intel_amt_http_detect.nasl");
  script_mandatory_keys("intel/amt/detected");

  script_tag(name:"summary", value:"Multiple potential security vulnerabilities in Intel Active
  Management Technology (AMT) may allow escalation of privilege, information disclosure, and/or
  denial of service (DoS).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-0092: Insufficient input validation in subsystem may allow an unauthenticated user to
  potentially enable escalation of privilege via physical access

  - CVE-2019-0094: Insufficient input validation in subsystem may allow an unauthenticated user to
  potentially enable denial of service via adjacent network access

  - CVE-2019-0096: Out of bound write in subsystem may allow an authenticated user to potentially
  enable escalation of privilege via adjacent network access

  - CVE-2019-0097: Insufficient input validation in subsystem may allow a privileged user to
  potentially enable denial of service via network access");

  script_tag(name:"affected", value:"Intel Active Management Technology version 11.0 through
  11.8.60, 11.10 through 11.11.60, 11.20 through 11.22.60 and 12.0 through 12.0.20.");

  script_tag(name:"solution", value:"Update to version 11.8.65, 11.11.65, 11.22.65, 12.0.35 or
  later.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00213.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.8.60")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.8.65");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.10", test_version2: "11.11.60")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.11.65");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.20", test_version2: "11.22.60")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.22.65");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.0.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.35");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
