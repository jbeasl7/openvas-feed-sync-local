# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153938");
  script_version("2025-08-27T05:39:13+0000");
  script_tag(name:"last_modification", value:"2025-08-27 05:39:13 +0000 (Wed, 27 Aug 2025)");
  script_tag(name:"creation_date", value:"2025-02-05 03:30:09 +0000 (Wed, 05 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-26 17:54:51 +0000 (Tue, 26 Aug 2025)");

  script_cve_id("CVE-2024-56197", "CVE-2025-24808", "CVE-2025-24972", "CVE-2025-46813");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 3.4.x < 3.4.0.beta5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-56197: Users can see other user's tagged PMs

  - CVE-2025-24808: Race condition when adding users to a group DM

  - CVE-2025-24972: Bypass user preference when adding users to chat groups

  - CVE-2025-46813: Private data leak on login-required Discourse sites");

  script_tag(name:"affected", value:"Discourse versions 3.4.x prior to 3.4.0.beta5.");

  script_tag(name:"solution", value:"Update to version 3.4.0.beta5 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-xmgr-g9cp-v239");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-hfcx-qjw6-573r");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-4p63-qw6g-4mv2");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-v3h7-c287-pfg9");

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

if (version_in_range_exclusive(version: version, test_version_lo: "3.4.0.beta", test_version_up: "3.4.0.beta5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.0.beta5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
