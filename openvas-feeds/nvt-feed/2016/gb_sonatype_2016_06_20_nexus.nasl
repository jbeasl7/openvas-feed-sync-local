# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sonatype:nexus";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105819");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Sonatype Nexus Repository Manager < 2.11.2 RCE Vulnerability");

  script_xref(name:"URL", value:"http://www.sonatype.org/advisories/archive/2016-06-20-Nexus/");

  script_tag(name:"impact", value:"The vulnerability allows for an unauthenticated attacker with
  network access to perform remote code exploits.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vulnerability is fixed in Nexus 2.11.2-01 and later.");

  script_tag(name:"summary", value:"Sonatype Nexus Repository Manager is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"affected", value:"All Nexus Repository Manager OSS/Pro versions up to and
  including 2.11.1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-07-21 12:28:37 +0200 (Thu, 21 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_sonatype_nexus_detect.nasl");
  script_mandatory_keys("nexus/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version: vers, test_version: "2.11.2.01" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.11.2.01" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
