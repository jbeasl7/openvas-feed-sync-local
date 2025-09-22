# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113628");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-01-21 15:30:23 +0000 (Tue, 21 Jan 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-19 03:15:00 +0000 (Wed, 19 Feb 2020)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-7106", "CVE-2020-7237");

  script_name("Cacti < 1.2.9 Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cacti_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Stored XSS vulnerability in data_sources.php, color_templates_item.php,
    graphs.php, graph_items.php, lib/api_automation.php, user_admin.php
    and user_group_admin.php, as demonstrated by the description parameter
    in data_sources.php (a raw string from the database that is displayed
    by $header to trigger the XSS).

  - Remote Code Execution (by privileged users) via shell metacharacters
    in the Performance Boost Debug Log field of poller_automation.php.
    OS commands are executed when a new poller cycle begins. The attacker
    must be authenticated and must have access to modify the Performance Settings.");

  script_tag(name:"impact", value:"Successful exploitation would have effects ranging from the attacker
  injection arbitrary HTML and JavaScript into the site to the attacker
  gaining full control over the target system.");

  script_tag(name:"affected", value:"Cacti prior to version 1.2.9.");

  script_tag(name:"solution", value:"Update to Cacti version 1.2.9 or later.");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00014.html");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/3191");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/3201");

  exit(0);
}

CPE = "cpe:/a:cacti:cacti";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "1.2.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2.9", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
