# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113369");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2019-04-15 11:12:47 +0000 (Mon, 15 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-17 17:18:00 +0000 (Wed, 17 Apr 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-10945", "CVE-2019-10946", "CVE-2019-11358");

  script_name("Joomla < 3.9.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"summary", value:"Joomla! is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The Media Manager component does not properly sanitize the folder parameter,
    allowing attackers to act outside the media manager root directory

  - The 'refresh list of helpsites' endpoint of com_users lacks access checks,
    allowing calls from unauthenticated users

  - The $.extend method of JQuery is vulnerable to Object.prototype pollution attacks (CVE-2019-11358)");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access sensitive information
  or execute arbitrary commands.");

  script_tag(name:"affected", value:"Joomla! through version 3.9.4.");

  script_tag(name:"solution", value:"Update to version 3.9.5.");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/777-20190401-core-directory-traversal-in-com-media");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/778-20190402-core-helpsites-refresh-endpoint-callable-for-unauthenticated-users");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre.html");

  exit(0);
}

CPE = "cpe:/a:joomla:joomla";

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( port: port, cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
path = infos["location"];

if( version_is_less( version: version, test_version: "3.9.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.5", install_path: path );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
