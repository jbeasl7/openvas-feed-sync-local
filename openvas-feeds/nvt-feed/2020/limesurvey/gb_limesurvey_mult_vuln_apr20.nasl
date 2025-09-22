# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113673");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-04-12 10:29:50 +0000 (Sun, 12 Apr 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-30 03:41:00 +0000 (Sat, 30 Jul 2022)");

  script_cve_id("CVE-2020-11455", "CVE-2020-11456");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 4.1.12 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-11455: path traversal vulnerability in application/controllers/admin/LimeSurveyFileManager.php

  - CVE-2020-11456: XSS vulnerability in application/views/admin/surveysgroups/surveySettings.php
    and application/models/SurveysGroups.php");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read and
  delete sensitive information or inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"LimeSurvey prior to version 4.1.11.");

  script_tag(name:"solution", value:"Update to version 4.1.12 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/48297");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/157112/LimeSurvey-4.1.11-Path-Traversal.html");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/48289");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/157114/LimeSurvey-4.1.11-Cross-Site-Scripting.html");

  exit(0);
}

CPE = "cpe:/a:limesurvey:limesurvey";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "4.1.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.1.12", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );