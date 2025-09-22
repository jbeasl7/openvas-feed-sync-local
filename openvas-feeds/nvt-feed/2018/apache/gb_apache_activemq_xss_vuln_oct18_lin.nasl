# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113278");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-10-25 11:29:28 +0200 (Thu, 25 Oct 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-14 02:57:00 +0000 (Sun, 14 Feb 2021)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-8006");

  script_name("Apache Active MQ 5.0.0 to 5.15.5 Authenticated XSS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/activemq/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to an authenticated XSS vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The issue exists due to improper data filtering of the QueueFilter parameter
  on the queue.jsp page.");

  script_tag(name:"impact", value:"An authenticated attacker may exploit the vulnerability to inject arbitrary
  JavaScript code into the page.");

  script_tag(name:"affected", value:"Apache Active MQ 5.0.0 through 5.15.5.");

  script_tag(name:"solution", value:"Update to version 5.15.6.");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2018-8006-announcement.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105156");

  exit(0);
}

CPE = "cpe:/a:apache:activemq";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.15.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.15.6" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
