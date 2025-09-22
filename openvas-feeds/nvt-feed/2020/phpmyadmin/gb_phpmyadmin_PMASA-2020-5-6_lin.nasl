# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144896");
  script_version("2024-02-13T05:06:26+0000");
  script_tag(name:"last_modification", value:"2024-02-13 05:06:26 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-11-06 03:06:36 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-30 22:15:00 +0000 (Tue, 30 Mar 2021)");

  script_cve_id("CVE-2020-26934", "CVE-2020-26935");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin < 4.9.6, 5.x < 5.0.3 Multiple Vulnerabilities (PMASA-2020-5, PMASA-2020-6) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_phpmyadmin_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - XSS relating to the transformation feature (CVE-2020-26934)

  - SQL injection vulnerability in SearchController (CVE-2020-26935)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to:

  - If an attacker sends a crafted link to the victim with the malicious JavaScript, when the victim clicks on the
    link, the JavaScript will run and complete the instructions made by the attacker (CVE-2020-26934)

  - An attacker could use this flaw to inject malicious SQL in to a query (CVE-2020-26935)");

  script_tag(name:"affected", value:"phpMyAdmin prior to version 4.9.6 and 5.x prior to 5.0.3.");

  script_tag(name:"solution", value:"Update to version 4.9.6, 5.0.3 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2020-5/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2020-6/");

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

if (version_is_less(version: version, test_version: "4.9.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.0", test_version2: "5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
