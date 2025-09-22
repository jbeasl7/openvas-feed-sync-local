# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:limesurvey:limesurvey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146199");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2021-07-01 03:02:29 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-02 15:05:00 +0000 (Fri, 02 Jul 2021)");

  script_cve_id("CVE-2020-22607");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 4.1.15 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"LimeSurvey is prone to a stored XSS vulnerability in the
  permission rules.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to inject arbitrary HTML
  and JavaScript into the site.");

  script_tag(name:"affected", value:"LimeSurvey version 4.1.14 and prior.");

  script_tag(name:"solution", value:"Update to version 4.1.15 or later.");

  script_xref(name:"URL", value:"https://account.limesurvey.org/pt/limesurvey-updates/2234-limesurvey-4-1-15-build-200402-released");
  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/commit/2aada33c76efbbc35d33c149ac02b1dc16a81f62");

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

if (version_is_less(version: version, test_version: "4.1.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
