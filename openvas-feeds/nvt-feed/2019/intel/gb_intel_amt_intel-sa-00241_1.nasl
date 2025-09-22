# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:intel:active_management_technology_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143286");
  script_version("2024-08-23T15:40:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 15:40:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2019-12-20 03:55:32 +0000 (Fri, 20 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-11132", "CVE-2019-11088", "CVE-2019-11131", "CVE-2019-0131",
                "CVE-2019-0166", "CVE-2019-11100");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology Multiple Vulnerabilities (INTEL-SA-00241)");

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

  - CVE-2019-11132: Cross site scripting (XSS) may allow a privileged user to potentially enable
  escalation of privilege via network access

  - CVE-2019-11088: Insufficient input validation may allow an unauthenticated user to potentially
  enable escalation of privilege via adjacent access

  - CVE-2019-11131: Logic issue may allow an unauthenticated user to potentially enable escalation
  of privilege via network access

  - CVE-2019-0131: Insufficient input validation may allow an unauthenticated user to potentially
  enable denial of service or information disclosure via adjacent access

  - CVE-2019-0166: Insufficient input validation may allow an unauthenticated user to potentially
  enable information disclosure via network access

  - CVE-2019-11100: Insufficient input validation may allow an unauthenticated user to potentially
  enable information disclosure via physical access");

  script_tag(name:"affected", value:"Intel Active Management Technology version 11.0 through
  11.8.65, 11.10 through 11.11.65, 11.20 through 11.22.65 and 12.0 through 12.0.35.");

  script_tag(name:"solution", value:"Update to version 11.8.70, 11.11.70, 11.22.70, 12.0.45 or
  later.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00241.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.8.65")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.8.70");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.10", test_version2: "11.11.65")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.11.70");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.20", test_version2: "11.22.65")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.22.70");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.0.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.45");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
