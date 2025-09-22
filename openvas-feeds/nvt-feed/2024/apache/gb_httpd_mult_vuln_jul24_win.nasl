# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114683");
  script_version("2025-08-07T05:44:51+0000");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"creation_date", value:"2024-07-01 14:37:18 +0000 (Mon, 01 Jul 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-21 15:08:56 +0000 (Wed, 21 Aug 2024)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-36387", "CVE-2024-38472", "CVE-2024-38473", "CVE-2024-38474",
                "CVE-2024-38475", "CVE-2024-38476", "CVE-2024-38477", "CVE-2024-39573");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server < 2.4.60 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-36387: Denial of Service (DoS) by Null pointer in websocket over HTTP/2

  - CVE-2024-38472: Windows UNC Server-Side Request Forgery (SSRF)

  - CVE-2024-38473: Proxy encoding problem

  - CVE-2024-38474: Weakness with encoded question marks in backreferences

  - CVE-2024-38475: Weakness in mod_rewrite when first segment of substitution matches filesystem
  path

  - CVE-2024-38476: May use exploitable/malicious backend application output to run local handlers
  via internal redirect

  - CVE-2024-38477: Crash resulting in DoS in mod_proxy via a malicious request

  - CVE-2024-39573: mod_rewrite proxy handler substitution");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.4.59 and prior.");

  script_tag(name:"solution", value:"Update to version 2.4.60 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.60");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "2.4.60")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.60", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
