# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807971");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2016-0734");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-27 20:29:00 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-05-05 17:11:01 +0530 (Thu, 05 May 2016)");

  script_name("Apache ActiveMQ Clickjacking Vulnerability (May 2016)");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl");
  script_mandatory_keys("apache/activemq/detected");

  script_xref(name:"URL", value:"https://activemq.apache.org/security-advisories.data/CVE-2016-0734-announcement.txt");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to a clickjacking vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the web-based administration console does not set an
  X-Frame-Options header in HTTP responses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct clickjacking attacks via a crafted web page.");

  script_tag(name:"affected", value:"Apache ActiveMQ Version 5.x before 5.13.2.");

  script_tag(name:"solution", value:"Upgrade to Apache ActiveMQ Version 5.13.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! appVer = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_in_range( version:appVer, test_version:"5.0.0", test_version2:"5.13.1" ) ) {
  report = report_fixed_ver( installed_version:appVer, fixed_version:"5.13.2" );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
