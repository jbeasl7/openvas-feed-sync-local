# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113081");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2018-01-12 12:46:47 +0100 (Fri, 12 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-26 15:09:00 +0000 (Fri, 26 Apr 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-6810");

  script_name("Apache Active MQ 5.14.1 XSS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/activemq/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache Active MQ 5.x before 5.14.1 is prone to an authenticated XSS vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper user data output validation.");

  script_tag(name:"affected", value:"Apache Active MQ 5.x before 5.14.1.");

  script_tag(name:"solution", value:"Update to Apache Active MQ 5.14.2 or above.");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2016-6810-announcement.txt");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/924a3a27fad192d711436421e02977ff90d9fc0f298e1efe6757cfbc@%3Cusers.activemq.apache.org%3E");

  exit(0);
}

CPE = "cpe:/a:apache:activemq";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) ) exit( 0 );

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.14.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.14.2" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
