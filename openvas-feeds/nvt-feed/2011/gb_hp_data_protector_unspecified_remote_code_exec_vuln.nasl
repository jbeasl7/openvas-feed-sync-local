# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:data_protector";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902531");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2011-1864");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP (OpenView Storage) Data Protector Unspecified RCE Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("hp_data_protector_installed.nasl");
  script_mandatory_keys("microfocus/data_protector/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary code in the context of the affected application.");

  script_tag(name:"affected", value:"HP (OpenView Storage) Data Protector versions 6.0, 6.10, and
  6.11.");

  script_tag(name:"insight", value:"The flaw is caused by an unspecified error, which allows remote
  attackers to execute arbitrary code via unknown vectors.");

  script_tag(name:"summary", value:"HP (OpenView Storage) Data Protector is prone to a remote code
  execution (RCE) vulnerability.");

  script_tag(name:"solution", value:"Update to version 6.12 or later.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"06.0" ) ||
    version_is_equal( version:vers, test_version:"06.10" ) ||
    version_is_equal( version:vers, test_version:"06.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"06.12" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
