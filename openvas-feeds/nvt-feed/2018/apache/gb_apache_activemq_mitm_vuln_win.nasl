# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112387");
  script_version("2024-02-29T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-29 05:05:39 +0000 (Thu, 29 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-09-20 14:15:00 +0200 (Thu, 20 Sep 2018)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-05 19:15:00 +0000 (Fri, 05 Mar 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11775");

  script_name("Apache Active MQ 5.0.0 - 5.15.5 Missing TLS Hostname Verification Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/activemq/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Active MQ is missing its TLS hostname verification.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"TLS hostname verification when using the Apache ActiveMQ Client was missing
  which could make the client vulnerable to a MITM attack between a Java application using the ActiveMQ client and
  the ActiveMQ server. This is now enabled by default.");

  script_tag(name:"affected", value:"Apache Active MQ 5.0.0 up to and including 5.15.5.");

  script_tag(name:"solution", value:"Update to Apache Active MQ 5.15.6 or later.");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2018-11775-announcement.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105335");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

if( version_in_range( version: version, test_version: "5.0.0", test_version2: "5.15.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.15.6" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
