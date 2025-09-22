# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145367");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-02-11 09:46:10 +0000 (Thu, 11 Feb 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-16 19:10:00 +0000 (Tue, 16 Feb 2021)");

  script_cve_id("CVE-2020-28644", "CVE-2020-28645");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 10.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Cross-Site Request Forgery in the ocs api (CVE-2020-28644)

  - Missing user validation is leading to information disclosure (CVE-2020-28645)");

  script_tag(name:"affected", value:"ownCloud versions prior to 10.6.");

  script_tag(name:"solution", value:"Update to version 10.6 or later.");

  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cross-site-request-forgery-in-the-ocs-api/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/missing-user-validation-leading-to-information-disclosure/");

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

if (version_is_less(version: version, test_version: "10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
