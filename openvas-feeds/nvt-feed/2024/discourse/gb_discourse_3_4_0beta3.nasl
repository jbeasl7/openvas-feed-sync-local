# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153672");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2024-12-20 04:19:48 +0000 (Fri, 20 Dec 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-26 02:16:43 +0000 (Tue, 26 Aug 2025)");

  script_cve_id("CVE-2024-52589", "CVE-2024-55948", "CVE-2025-23023");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 3.4.x < 3.4.0.beta3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-52589: Moderators can view Screened emails even when the 'moderators view emails'
  option is disabled

  - CVE-2024-55948: Anonymous cache poisoning via XHR requests

  - CVE-2025-23023: Anonymous cache poisoning via request headers");

  script_tag(name:"affected", value:"Discourse versions 3.4.x prior to 3.4.0.beta3.");

  script_tag(name:"solution", value:"Update to version 3.4.0.beta3 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-cqw6-rr3v-8fff");
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

if (version_in_range_exclusive(version: version, test_version_lo: "3.4.0.beta", test_version_up: "3.4.0.beta3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.4.0.beta3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
