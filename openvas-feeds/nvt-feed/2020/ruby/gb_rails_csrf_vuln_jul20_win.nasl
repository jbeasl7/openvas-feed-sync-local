# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113714");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2020-07-06 10:10:26 +0000 (Mon, 06 Jul 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-20 17:47:00 +0000 (Fri, 20 Nov 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-8166");

  script_name("Ruby on Rails < 5.2.5, 6.x < 6.0.4 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("rails/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Ruby on Rails is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An attacker can use a global CSRF token,
  as can be found in the authenticity_token meta tag, to forge form-specific CSRF tokens.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacer
  to perform actions in the context of another user.");

  script_tag(name:"affected", value:"Ruby on Rails through version 5.2.4 and versions 6.0.0 through 6.0.3.");

  script_tag(name:"solution", value:"Update to version 5.2.5, 6.0.4 or later.");

  script_xref(name:"URL", value:"https://hackerone.com/reports/732415");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.2.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.2.5", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "6.0.0", test_version2: "6.0.3.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.0.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
