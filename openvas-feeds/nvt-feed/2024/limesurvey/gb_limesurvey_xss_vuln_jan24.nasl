# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:limesurvey:limesurvey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127723");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-04-09 08:19:19 +0000 (Tue, 09 Apr 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2024-24506");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 5.6.49-231212 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"LimeSurvey fails to properly validate user-supplied input on
  both client and server sides, despite some protective measures. The 'Administrator email
  address:' field within the 'General Setting' functionality permits the insertion of special
  characters, enabling the injection of malicious JavaScript payloads. These payloads are stored in
  the database and executed when the user saves or reloads the page.");

  script_tag(name:"affected", value:"LimeSurvey prior to version 5.6.49-231212.");

  script_tag(name:"solution", value:"Update to version 5.6.49-231212 or later.");

  script_xref(name:"URL", value:"https://bugs.limesurvey.org/bug_relationship_graph.php?bug_id=19364&graph=relation");

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

if( version_is_less( version: version, test_version: "5.6.49-231212" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.6.49-231212", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
