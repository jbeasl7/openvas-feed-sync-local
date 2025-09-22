# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148970");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2022-12-02 06:19:04 +0000 (Fri, 02 Dec 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-01 20:28:00 +0000 (Thu, 01 Dec 2022)");

  script_cve_id("CVE-2022-41921", "CVE-2022-41944");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 2.9.0.beta13 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-41921: Users can post chat messages of an unlimited length, which can cause a denial
  of service for other users when posting huge amounts of text.

  - CVE-2022-41944: Under certain conditions, a user can see notifications for topics they no
  longer have access to. If there is sensitive information in the topic title, it will therefore
  have been exposed.");

  script_tag(name:"affected", value:"Discourse prior to version 2.9.0.beta13.");

  script_tag(name:"solution", value:"Update to version 2.9.0.beta13 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-mfh7-6cv6-qccc");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-354r-jpj5-53c2");

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

if (version_in_range(version: version, test_version: "2.9.0.beta1", test_version2: "2.9.0.beta12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.0.beta13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
