# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:intel:active_management_technology_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144922");
  script_version("2024-08-23T15:40:37+0000");
  script_tag(name:"last_modification", value:"2024-08-23 15:40:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2020-11-13 04:32:06 +0000 (Fri, 13 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-18 18:29:00 +0000 (Wed, 18 Nov 2020)");

  script_cve_id("CVE-2020-8746", "CVE-2020-8747", "CVE-2020-8749", "CVE-2020-8752",
                "CVE-2020-8753", "CVE-2020-8754", "CVE-2020-8757", "CVE-2020-8760",
                "CVE-2020-12356");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology Multiple Vulnerabilities (INTEL-SA-00391)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_intel_amt_http_detect.nasl");
  script_mandatory_keys("intel/amt/detected");

  script_tag(name:"summary", value:"Intel Active Management Technology (AMT) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-8746: Integer overflow may allow an unauthenticated user to potentially enable denial
  of service via adjacent access

  - CVE-2020-8747: Out-of-bounds read may allow an unauthenticated user to potentially enable
  information disclosure and/or  denial of service via network access

  - CVE-2020-8749: Out-of-bounds read may allow an unauthenticated user to potentially enable
  escalation of privilege via adjacent access

  - CVE-2020-8752: Out-of-bounds write in IPv6 subsystem may allow an unauthenticated user to
  potentially enable escalation of privileges via network access

  - CVE-2020-8753: Out-of-bounds read in DHCP subsystem may allow an unauthenticated user to
  potentially enable information disclosure via network access

  - CVE-2020-8754: Out-of-bounds read may allow an unauthenticated user to potentially enable
  information disclosure via network access

  - CVE-2020-8757: Out-of-bounds read may allow a privileged user to potentially enable escalation
  of privilege via local access

  - CVE-2020-8760: Integer overflow may allow a privileged user to potentially enable escalation of
  privilege via local access

  - CVE-2020-12356: Out-of-bounds read may allow a privileged user to potentially enable
  information disclosure via local access");

  script_tag(name:"affected", value:"Intel Active Management Technology versions before 11.8.80,
  11.12.80, 11.22.80, 12.0.70 or 14.0.45.");

  script_tag(name:"solution", value:"Update to version 11.8.80, 11.12.80, 11.22.80, 12.0.70,
  14.0.45 or later.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00391.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "11.8.80")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.8.80");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.10", test_version2: "11.12.79")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.12.80");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.20", test_version2: "11.22.79")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.22.80");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.0.69")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.0.70");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "14.0", test_version2: "14.0.44")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.0.45");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
