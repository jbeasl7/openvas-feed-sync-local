# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108169");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-05-24 08:42:44 +0200 (Wed, 24 May 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_cve_id("CVE-2017-6087", "CVE-2017-6088");
  script_name("Eyes Of Network (EON) <= 5.0 Multiple Security Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_consolidation.nasl");
  script_mandatory_keys("eyesofnetwork/detected");

  script_xref(name:"URL", value:"https://www.eyesofnetwork.com/?p=1912");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/03/23/5");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2017/q1/667");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97084");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97109");

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to multiple arbitrary code execution
  and SQL injection vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Eyes Of Network (EON) is prone to multiple:

  - SQL injection vulnerabilities which allow remote authenticated users to execute arbitrary SQL commands
  via the (1) bp_name, (2) display, (3) search, or (4) equipment parameter to module/monitoring_ged/ged_functions.php
  or the (5) type parameter to monitoring_ged/ajax.php.

  - code execution vulnerabilities via shell metacharacters in the selected_events[] parameter in the (1) acknowledge,
  (2) delete, or (3) ownDisown function in module/monitoring_ged/ged_functions.php or the (4) module parameter to module/index.php.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to:

  - execute arbitrary code within the context of the affected application

  - compromise the application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"Version 5.0 and prior.");

  script_tag(name:"solution", value:"Update to version 5.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"5.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.1" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
