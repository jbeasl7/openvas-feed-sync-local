# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113217");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2018-06-27 10:30:30 +0200 (Wed, 27 Jun 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-30 13:08:00 +0000 (Thu, 30 Aug 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11587", "CVE-2018-11588", "CVE-2018-11589");

  script_name("Centreon <= 2.8.23 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_centreon_web_http_detect.nasl");
  script_mandatory_keys("centreon_web/detected");

  script_tag(name:"summary", value:"Centreon Web is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Remote Code Execution vulnerability via the 'RPN' value
    in the Virtual Metric form in centreonGraph.class.php.

  - Multiple SQL injection vulnerabilities via the searchU parameter in viewLogs.php,
    the id parameter in GetXMLHost.php, the chartId parameter in ExportCSVServiceData.php,
    the searchCurve parameter in listComponentTemplates.php
    and the host_id parameter in makeXML_ListMetrics.php

  - An authenticated user may inject a payload into the username or command description,
    resulting in stored XSS.");
  script_tag(name:"affected", value:"Centreon Web through version 2.8.23.");
  script_tag(name:"solution", value:"Update to version 2.8.24.");

  script_xref(name:"URL", value:"https://documentation.centreon.com/docs/centreon/en/latest/release_notes/centreon-2.8/centreon-2.8.24.html");

  exit(0);
}

CPE = "cpe:/a:centreon:centreon";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.8.24" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.24" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
