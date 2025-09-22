# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106264");
  script_version("2024-01-25T14:38:15+0000");
  script_tag(name:"last_modification", value:"2024-01-25 14:38:15 +0000 (Thu, 25 Jan 2024)");
  script_tag(name:"creation_date", value:"2016-09-19 11:58:34 +0700 (Mon, 19 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-19 18:45:00 +0000 (Fri, 19 May 2017)");

  script_cve_id("CVE-2016-4857");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Enterprise 6.2.x < 6.2.11, 6.3.x < 6.3.6, 6.4.x < 6.4.2 Open Redirect Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_http_detect.nasl");
  script_mandatory_keys("splunk/detected");

  script_tag(name:"summary", value:"Splunk Enterprise is prone to an open redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Splunk Enterprise is affected by a vulnerability that could
  permit an attacker to redirect a user to an attacker controlled website.");

  script_tag(name:"impact", value:"When accessing a specially crafted URL, the user may be
  redirected to an arbitrary website. As a result, the user may become a victim of a phishing
  attack.");

  script_tag(name:"affected", value:"Splunk Enterprise versions 6.2.x through 6.4.x.");

  script_tag(name:"solution", value:"Update to version 6.4.2, 6.3.6, 6.2.11 or later.");

  script_xref(name:"URL", value:"https://www.splunk.com/view/SP-CAAAPQM");

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

if (version =~ "^6\.4") {
  if (version_is_less(version: version, test_version: "6.4.2")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.4.2", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^6\.3") {
  if (version_is_less(version: version, test_version: "6.3.6")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.3.6", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}


if (version =~ "^6\.2") {
  if (version_is_less(version: version, test_version: "6.2.11")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.2.11", install_path: location);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
