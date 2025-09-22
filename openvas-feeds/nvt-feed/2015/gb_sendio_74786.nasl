# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sendio:sendio";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105293");
  script_cve_id("CVE-2014-0999", "CVE-2014-8391");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2024-03-01T14:37:10+0000");

  script_name("Sendio ESP Multiple Information Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74786");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Sendio before 7.2.4 includes the session identifier in URLs in emails, which allows remote attackers to obtain sensitive information and hijack
sessions by reading the jsessionid parameter in the Referrer HTTP header.");

  script_tag(name:"solution", value:"Updates are available");

  script_tag(name:"summary", value:"Sendio is prone to multiple information disclosure vulnerabilities");
  script_tag(name:"affected", value:"Sendio before 7.2.4");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2024-03-01 14:37:10 +0000 (Fri, 01 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-06-10 11:20:38 +0200 (Wed, 10 Jun 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_sendio_detect.nasl");
  script_mandatory_keys("sendio/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ! typ = get_kb_item("sendio/" + port + "/typ") )
  exit( 0 );

if( int( typ ) < 7 ) VULN = TRUE;

if( int( typ ) == 7 )
{
  if( version_is_less( version: vers, test_version: "7.2.4" ) )
  {
    VULN = TRUE;
  }
}

if( VULN )
{
  report = 'Installed version: Sendio ' + typ + ' (' + vers + ')\n' +
           'Fixed version:     7.2.4';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
