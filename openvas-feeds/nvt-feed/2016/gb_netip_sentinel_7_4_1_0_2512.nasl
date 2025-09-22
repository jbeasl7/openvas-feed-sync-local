# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netiq:sentinel";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105619");
  script_cve_id("CVE-2015-0851", "CVE-2014-3576");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-11-03T05:05:46+0000");

  script_name("Multiple Security issues with NetIQ Sentinel");

  script_xref(name:"URL", value:"https://www.netiq.com/documentation/sentinel-74/s741_release_notes/data/s741_release_notes.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version/revision is present on the target host.");

  script_tag(name:"insight", value:"The following security vulnerabilities are resolved with Sentinel 7.4.1:

  - Sentinel 7.4.1 includes Java 8 update 65, which includes fixes for several security vulnerabilities.

  - Denial of Service

  - Java Deserialization");

  script_tag(name:"solution", value:"Update to NetIQ Sentinel 7.4 SP1 (Sentinel 7.4.1.0) Build 2512 or higher");

  script_tag(name:"summary", value:"Sentinel 7.4.1 resolves multiple security vulnerabilities");
  script_tag(name:"affected", value:"NetIQ Sentinel < 7.4 SP1 (Sentinel 7.4.1.0) Build 2512");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-27 20:29:00 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-04-21 17:08:06 +0200 (Thu, 21 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_netiq_sentinel_detect.nasl");
  script_mandatory_keys("netiq_sentinel/version", "netiq_sentinel/rev");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:version, test_version:'7.4' ) ) VULN = TRUE;
if( version =~ "^7\.4" )
{
  if( rev = get_kb_item( "netiq_sentinel/rev" ) )
  {
    if( int( rev ) < int( 2512 ) ) VULN = TRUE;
  }
}

if( VULN )
{
  report = 'Installed version:  ' + version + '\n';
  if( rev ) report += 'Installed revision: ' + rev + '\n';
  report += 'Fixed version:      7.4 SP1 (Sentinel 7.4.1.0) Build 2512\n';

  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

