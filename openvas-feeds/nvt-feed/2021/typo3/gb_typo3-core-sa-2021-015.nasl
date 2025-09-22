# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:typo3:typo3";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146866");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2021-10-07 12:08:31 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-09 02:51:00 +0000 (Sat, 09 Oct 2021)");

  script_cve_id("CVE-2021-41114");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("TYPO3 HTTP Host Header Injection Vulnerability (TYPO3-CORE-SA-2021-015)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_http_detect.nasl");
  script_mandatory_keys("typo3/detected");

  script_tag(name:"summary", value:"TYPO3 is prone to an HTTP host header injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"TYPO3 CMS is susceptible to host spoofing due to improper
  validation of the HTTP Host header. TYPO3 uses the HTTP Host header, for example, to generate
  absolute URLs during the frontend rendering process. Since the host header itself is provided by
  the client, it can be forged to any value, even in a name-based virtual hosts environment.");

  script_tag(name:"affected", value:"TYPO3 version 11.0.0 through 11.4.0.");

  script_tag(name:"solution", value:"Update to version 11.5.0 or later.");

  script_xref(name:"URL", value:"https://typo3.org/security/advisory/typo3-core-sa-2021-015");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "[0-9]+\.[0-9]+\.[0-9]+")) # nb: Version might not be exact enough
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "11.0.0", test_version2: "11.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.5.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
