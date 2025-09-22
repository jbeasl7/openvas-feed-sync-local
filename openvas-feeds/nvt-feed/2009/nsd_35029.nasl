# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nlnetlabs:nsd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100209");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-24 11:22:37 +0200 (Sun, 24 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("NSD (Name Server Daemon) 'packet.c' Off-By-One Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("nsd_version.nasl");
  script_mandatory_keys("nsd/installed");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow attackers to
  execute arbitrary code within the context of the affected server.
  Failed exploit attempts will result in a denial-of-service condition.");

  script_tag(name:"affected", value:"Versions prior to NSD 3.2.2 are vulnerable.");

  script_tag(name:"solution", value:"Update to version 3.2.2 or later.");

  script_tag(name:"summary", value:"NSD is prone to an off-by-one buffer-overflow vulnerability
  because the server fails to perform adequate boundary checks on user-supplied data.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.nlnetlabs.nl/projects/nsd/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35029");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"3.2.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.2.2" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );