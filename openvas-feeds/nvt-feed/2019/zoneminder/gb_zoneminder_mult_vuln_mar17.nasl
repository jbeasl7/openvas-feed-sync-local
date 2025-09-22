# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:zoneminder:zoneminder";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112507");
  script_version("2024-11-05T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-02-05 16:56:11 +0100 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-07 12:58:00 +0000 (Tue, 07 Mar 2017)");

  script_cve_id("CVE-2016-10201", "CVE-2016-10202", "CVE-2016-10203", "CVE-2016-10204",
                "CVE-2016-10205", "CVE-2016-10206");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ZoneMinder <= 1.30.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_zoneminder_http_detect.nasl");
  script_mandatory_keys("zoneminder/detected");

  script_tag(name:"summary", value:"ZoneMinder is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Multiple cross-site scripting (XSS)

  - Session fixation

  - Cross-site request forgery (CSRF)

  - SQL injection (SQLi)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute HTML
  or JavaScript code via multiple parameters, to hijack web sessions, to execute arbitrary SQL
  commands or to have other unspecified impact on the application and its host system.");

  script_tag(name:"affected", value:"ZoneMinder version 1.30.1 and prior.");

  script_tag(name:"solution", value:"Update to version 1.30.2 or later.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/02/05/1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97116");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97114");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/zoneminder/releases");

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

if (version_is_less_equal(version: version, test_version: "1.30.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.30.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
