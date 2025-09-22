# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:s9y:serendipity";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108060");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-5474", "CVE-2017-5475", "CVE-2017-5476", "CVE-2017-5609");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-19 15:12:00 +0000 (Tue, 19 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-01-30 11:00:00 +0100 (Mon, 30 Jan 2017)");
  script_name("Serendipity <= 2.0.5 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl");
  script_mandatory_keys("Serendipity/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95656");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95659");
  script_xref(name:"URL", value:"https://blog.s9y.org/archives/272-Serendipity-2.1-First-Release-Candidate.html");

  script_tag(name:"summary", value:"Serendipity is prone to multiple vulnerabilities because of
  insufficient CSRF protection / sanitized user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Cross-site request forgery (CSRF) for the installation of an event plugin or a sidebar plugin

  - Cross-site request forgery (CSRF) in deleting any comments

  - Open redirect vulnerability in comment.php

  - SQL injection vulnerability in include/functions_entries.inc.php");

  script_tag(name:"impact", value:"Successfully exploiting these issues allows remote attacker to:

  - redirect users to arbitrary web sites and conduct phishing attacks via a URL in the HTTP Referer header

  - perform certain unauthorized actions and gain access to the affected application

  - execute arbitrary SQL commands via the cat parameter

  Other attacks are also possible.");

  script_tag(name:"affected", value:"Serendipity versions up to 2.0.5.");

  script_tag(name:"solution", value:"Update to version 2.1-rc1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.0.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.1-rc1 or later" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
