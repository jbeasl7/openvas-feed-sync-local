# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:data_protector";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801963");
  script_version("2026-04-28T06:28:06+0000");
  script_tag(name:"last_modification", value:"2026-04-28 06:28:06 +0000 (Tue, 28 Apr 2026)");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2011-2399");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP (OpenView Storage) Data Protector Media Management Daemon DoS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("hp_data_protector_installed.nasl");
  script_mandatory_keys("microfocus/data_protector/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of
  service condition.");

  script_tag(name:"affected", value:"HP (OpenView Storage) Data Protector Manager version 6.11 and
  prior.");

  script_tag(name:"insight", value:"The flaw is caused by an error in the Media Management Daemon
  (mmd), which could be exploited by remote attackers to crash an affected server.");

  script_tag(name:"summary", value:"HP (OpenView Storage) Data Protector Manager is prone to a
  denial of service (DoS) vulnerability.");

  script_tag(name:"solution", value:"Update to version 6.12 or later.");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=131188787531606&w=2");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/103547/HPSBMU02669-SSRT100346-3.txt");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"06.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"06.12" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
