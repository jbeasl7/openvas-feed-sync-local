# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114851");
  script_version("2024-11-07T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-11-07 05:05:35 +0000 (Thu, 07 Nov 2024)");
  # nb: This was initially a single VT which got split into multiple later. As we covered all flaws
  # at this time the original creation_date has been kept in all later created VTs.
  script_tag(name:"creation_date", value:"2023-10-20 08:47:30 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-05 16:45:52 +0000 (Tue, 05 Nov 2024)");

  script_cve_id("CVE-2024-45802");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Multiple DoS Vulnerabilities (GHSA-f975-v7qw-q7hj, SQUID-2024:4)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_tag(name:"summary", value:"Squid is prone to multiple denial of service (DoS)
  vulnerabilities due to multiple issues in ESI.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to Input Validation, Premature Release of Resource During
  Expected Lifetime, and Missing Release of Resource after Effective Lifetime bugs, Squid is
  vulnerable to Denial of Service attacks by a trusted server against all clients using the proxy.

  These flaws were part of the 'Squid Caching Proxy Security Audit: 55 vulnerabilities and 35 0days'
  publication in October 2023 and filed as:

  - Memory Leak in ESI Error Processing

  - Assertion in ESI Header Handling

  - Use-After-Free in ESI 'Try' (and 'Choose') Processing

  - Use-After-Free in ESI Expression Evaluation

  - Assertion Due to 0 ESI 'when' Checking

  - Assertion Using ESI's When Directive

  - Assertion in ESI Variable Assignment (String)

  - Assertion in ESI Variable Assignment

  - Null Pointer Dereference In ESI's esi:include and esi:when");

  script_tag(name:"affected", value:"Squid version 3.0 through 6.x.");

  script_tag(name:"solution", value:"Update to version 7.0 or later.");

  # nb: While the advisory also includes a reference to esi-underflow.html it seems this has been
  # already fixed in an older version and is tracked as CVE-2024-37894
  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-f975-v7qw-q7hj");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/");
  script_xref(name:"URL", value:"https://joshua.hu/squid-security-audit-35-0days-45-exploits");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/10/11/3");
  script_xref(name:"URL", value:"https://gist.github.com/rousskov/9af0d33d2a1f4b5b3b948b2da426e77d");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/esi-when-assert-0.html");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/esi-when-assert-1.html");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/esi-nullpointer.html");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/esi-uaf.html");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/esi-assignassert.html");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/esi-assignassert-2.html");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/esi-uaf-crash.html");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/esi-memleak.html");
  script_xref(name:"URL", value:"https://megamansec.github.io/Squid-Security-Audit/esi-assert-header.html");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.0", test_version_up: "7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
