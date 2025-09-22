# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:limesurvey:limesurvey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103725");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-12 13:18:52 +0000 (Fri, 12 Jul 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-39063");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 6.5.14 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey is prone to a cross-site request forgery (CSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross Site Request Forgery (CSRF) via the insufficient
  validation of the YII_CSRF_TOKEN that is only checked when passed in the body of POST requests,
  but the same check isn't performed in the equivalent GET requests.");

  script_tag(name:"affected", value:"LimeSurvey prior to version 6.5.14.");

  script_tag(name:"solution", value:"Update to version 6.5.14 or later.");

  script_xref(name:"URL", value:"https://github.com/sysentr0py/CVEs/tree/main/CVE-2024-39063");
  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/pull/3880/commits/78140ce57a9a1ac24af15ab7121fb58acf42e88f");
  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/blob/master/docs/release_notes.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "6.5.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.5.14", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
