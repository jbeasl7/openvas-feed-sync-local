# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:banu:tinyproxy";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111081");
  script_version("2024-03-12T05:06:30+0000");
  script_cve_id("CVE-2012-3505");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-03-12 05:06:30 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-02-01 11:00:00 +0100 (Mon, 01 Feb 2016)");
  script_name("Tinyproxy < 1.8.4 Multiple DoS Vulnerabilities");
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("sw_tinyproxy_http_detect.nasl");
  script_mandatory_keys("tinyproxy/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55099");

  script_tag(name:"summary", value:"Tinyproxy is prone to multiple remote denial of service (DoS)
  vulnerabilities that affect the 'OpenSSL' extension.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful attacks will cause the application to consume
  excessive memory, creating a denial-of-service condition.");

  script_tag(name:"affected", value:"Tinyproxy versions prior to 1.8.4.");

  script_tag(name:"solution", value:"Update to version 1.8.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"1.8.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.8.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
