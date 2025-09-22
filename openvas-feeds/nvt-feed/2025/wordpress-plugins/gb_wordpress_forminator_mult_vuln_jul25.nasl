# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:incsub:forminator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127918");
  script_version("2025-07-07T05:42:05+0000");
  script_tag(name:"last_modification", value:"2025-07-07 05:42:05 +0000 (Mon, 07 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-03 10:10:00 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-02 05:15:27 +0000 (Wed, 02 Jul 2025)");

  script_cve_id("CVE-2025-6463", "CVE-2025-6464");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Forminator Plugin < 1.44.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/forminator/detected");

  script_tag(name:"summary", value:"The WordPress plugin 'Forminator' is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2025-6463: An arbitrary file deletion due to insufficient file path validation in the
  'entry_delete_upload_files' function

  - CVE-2025-6464:. A PHP Object Injection via deserialization of untrusted input in the
  'entry_delete_upload_files' function");

  script_tag(name:"affected", value:"WordPress Forminator plugin prior to version 1.44.3.");

  script_tag(name:"solution", value:"Update to version 1.44.3 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/6dc9b4cb-d36b-4693-a7b9-1dad123b6639");
  script_xref(name:"URL", value:"https://www.wordfence.com/threat-intel/vulnerabilities/id/6707aa4c-c652-42c0-bdb9-00be984e7271");

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

if( version_is_less( version:version, test_version:"1.44.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.44.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
