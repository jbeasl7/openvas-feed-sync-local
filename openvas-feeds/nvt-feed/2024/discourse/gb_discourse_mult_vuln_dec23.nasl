# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124603");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2024-02-05 09:29:22 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-25 15:42:48 +0000 (Thu, 25 Jan 2024)");

  script_cve_id("CVE-2023-48297", "CVE-2023-49099", "CVE-2024-21655");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 3.1.4, 3.2.x < 3.2.0.beta4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-48297: Message serializer uses the full list of expanded chat mentions which can lead
 to a very long  array of users.

  - CVE-2023-49099: Under very specific circumstances, secure upload URLs associated with posts can
 be accessed by guest users even when login is required.

  - CVE-2024-21655: For fields that are client editable, limits on sizes are often not imposed at
 all or are too generous. This would allow a malicious actor to cause a Discourse instance to use
 excessive disk space and also often excessive bandwidth.");

  script_tag(name:"affected", value:"Discourse prior to version 3.1.4 and 3.2.x prior to
  3.2.0.beta4.");

  script_tag(name:"solution", value:"Update to version 3.1.4, 3.2.0.beta4 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-hf2v-r5xm-8p37");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-m5fc-94mm-38fx");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-j67x-x6mq-pwv4");

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

if (version_is_less(version: version, test_version: "3.1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "3.2.0.beta1", test_version_up: "3.2.0.beta4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.0.beta4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
