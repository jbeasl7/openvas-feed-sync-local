# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:collabora:online";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126685");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-03-13 08:40:10 +0000 (Wed, 13 Mar 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-27 03:01:27 +0000 (Thu, 27 Feb 2025)");

  script_cve_id("CVE-2024-25114");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Collabora CODE / Collabora Online < 21.11.9.4, 22.x < 22.05.22, 23.x < 23.05.9 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_collabora_libreoffice_online_http_detect.nasl");
  script_mandatory_keys("collabora_libreoffice/online/detected");

  script_tag(name:"summary", value:"Collabora CODE (Collabora Online Development Edition) and
  Collabora Online is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Each document in Collabora Online is opened by a separate 'Kit'
  instance in a different 'jail' with a unique directory 'jailID' name. For security reasons, this
  directory name is randomly generated and should not be given out to the client.

  In affected versions of Collabora Online it is possible to use the CELL() function, with the
  'filename' argument, in the spreadsheet component to get a path which includes this JailID.");

  script_tag(name:"affected", value:"Collabora CODE / Collabora Online versions prior to 21.11.9.4,
  22.x prior to 22.05.22, 23.x prior to 23.05.9.");

  script_tag(name:"solution", value:"Update to version 21.11.9.4, 22.05.22, 23.05.9 or later.");

  script_xref(name:"URL", value:"https://github.com/CollaboraOnline/online/security/advisories/GHSA-2fh2-ppjf-p3xv");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less(version: version, test_version: "21.11.9.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "21.11.9.4", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "22.0", test_version_up: "22.05.22" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "22.05.22", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

if( version_in_range_exclusive( version: version, test_version_lo: "23.0", test_version_up: "23.05.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "23.05.9", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
