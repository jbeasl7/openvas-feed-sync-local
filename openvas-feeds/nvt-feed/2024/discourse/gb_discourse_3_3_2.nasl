# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170891");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-10-23 07:31:18 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-19 01:11:16 +0000 (Sat, 19 Oct 2024)");

  script_cve_id("CVE-2024-45051", "CVE-2024-45297", "CVE-2024-47772", "CVE-2024-47773",
                "CVE-2024-55948", "CVE-2025-23023");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 3.3.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-45051: Bypass of email address validation via encoded email addresses

  - CVE-2024-45297: Prevent topic list filtering by hidden tags for unauthorized users

  - CVE-2024-47772: XSS via chat excerpts when CSP disabled

  - CVE-2024-47773: Anonymous cache poisoning via XHR requests

  - CVE-2024-55948: Anonymous cache poisoning via XHR requests

  - CVE-2025-23023: Anonymous cache poisoning via request headers");

  script_tag(name:"affected", value:"Discourse prior to version 3.3.2.");

  script_tag(name:"solution", value:"Update to version 3.3.2 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-2vjv-pgh4-6rmq");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-58xw-3qr3-53gp");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-67mh-xhmf-c56h");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-58vv-9j8h-hw2v");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-2352-252q-qc82");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-5h4h-2f46-r3c7");

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

if (version_is_less(version: version, test_version: "3.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
