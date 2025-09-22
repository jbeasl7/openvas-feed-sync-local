# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ilias:ilias";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117948");
  script_version("2023-11-22T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-11-22 05:05:24 +0000 (Wed, 22 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-01-28 09:13:52 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-01 18:34:00 +0000 (Fri, 01 Jul 2022)");

  script_cve_id("CVE-2021-44832");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ILIAS <= 5.4.26, 6.x <= 6.14, 7.x <= 7.6 ilServer Log4j RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ilias_http_detect.nasl");
  script_mandatory_keys("ilias/detected");

  script_tag(name:"summary", value:"The ilServer Java component of ILIAS is using a version of the
  Apache Log4j library which is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaw exists in the Log4j library used by the
  ilServer component:

  Apache Log4j2 is vulnerable to a remote code execution (RCE) attack when a configuration uses a
  JDBC Appender with a JNDI LDAP data source URI when an attacker has control of the target LDAP
  server.");

  script_tag(name:"affected", value:"The ilServer Java component in ILIAS versions 5.4.26 and prior,
  6.x through 6.16 and 7.x through to 7.7.");

  script_tag(name:"solution", value:"Update to ILIAS version 6.17, 7.8 or later.");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/LOG4J2-3293");
  script_xref(name:"URL", value:"https://logging.apache.org/log4j/2.x/security.html");
  script_xref(name:"URL", value:"https://github.com/ILIAS-eLearning/ILIAS/compare/v7.7...v7.8");
  script_xref(name:"URL", value:"https://github.com/ILIAS-eLearning/ILIAS/commit/96a74ff6f61308545727336321efd1a0283d4835");
  script_xref(name:"URL", value:"https://github.com/ILIAS-eLearning/ILIAS/compare/v6.16...v6.17");
  script_xref(name:"URL", value:"https://github.com/ILIAS-eLearning/ILIAS/commit/5369a55002a3885764b851115fcb9c305b5088ad");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# nb: There was no fix to the 5.x branch since updating to Log4j 2.17.0 (2.17.1 would include the fix):
# https://github.com/ILIAS-eLearning/ILIAS/tree/v5.4.26/Services/WebServices/RPC/lib/jars
if (version_is_less_equal(version: version, test_version: "5.4.26")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.17")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
