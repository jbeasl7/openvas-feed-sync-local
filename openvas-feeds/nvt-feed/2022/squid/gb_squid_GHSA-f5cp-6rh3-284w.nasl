# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148471");
  script_version("2024-11-01T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-01 05:05:36 +0000 (Fri, 01 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-07-19 02:34:25 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-27 17:26:00 +0000 (Wed, 27 Jul 2022)");

  script_cve_id("CVE-2021-46784");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid 2.0 - 4.17, 5.0.1 < 5.6 DoS Vulnerability (GHSA-f5cp-6rh3-284w, SQUID-2021:7)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to improper buffer management Squid is vulnerable to a
  denial of service attack when processing Gopher server responses.

  This flaw was part of the 'Squid Caching Proxy Security Audit: 55 vulnerabilities and 35 0days'
  publication in October 2023 and filed as 'Assertion in Gopher Response Handling'.");

  script_tag(name:"affected", value:"Squid version 2.0 through 4.17 and 5.0.1 through 5.5.");

  script_tag(name:"solution", value:"Update to version 5.6 or later.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-f5cp-6rh3-284w");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/");
  script_xref(name:"URL", value:"https://joshua.hu/squid-security-audit-35-0days-45-exploits");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/11/3");
  script_xref(name:"URL", value:"https://gist.github.com/rousskov/9af0d33d2a1f4b5b3b948b2da426e77d");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/gopher-assert.html");

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

if (version_in_range(version: version, test_version: "2.0", test_version2: "4.17") ||
    version_in_range(version: version, test_version: "5.0.1", test_version2: "5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
