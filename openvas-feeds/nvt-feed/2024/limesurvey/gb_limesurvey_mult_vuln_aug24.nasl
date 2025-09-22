# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:limesurvey:limesurvey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131033");
  script_version("2024-09-17T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-09-17 05:05:45 +0000 (Tue, 17 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-05 10:27:00 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2024-42901", "CVE-2024-42902");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("LimeSurvey < 6.5.14 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_limesurvey_detect.nasl");
  script_mandatory_keys("limesurvey/http/detected");

  script_tag(name:"summary", value:"LimeSurvey is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-42901: LimeSurvey doesn't sanitize the name of the csv file used to import users. This
  results in a stored-XSS if an attacker with high privileges specifies a malicious payload as the
  csv file name.

  - CVE-2024-42902: Kcfinder file manager uses the 'js_localize.php' function to set the user's
  language by taking the language file name from the 'lng' query string parameter, without properly
  sanitizing it. This allows an attacker to specify an arbitrary file to include and execute them,
  resulting in a local file inclusion (LFI).");

  script_tag(name:"affected", value:"LimeSurvey version 6.5.14 and probably prior.");

  script_tag(name:"solution", value:"Update to version 6.5.14 or later.");

  script_xref(name:"URL", value:"https://github.com/sysentr0py/CVEs/tree/main/CVE-2024-42902");
  script_xref(name:"URL", value:"https://github.com/LimeSurvey/LimeSurvey/blob/master/docs/release_notes.txt#L172");

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
