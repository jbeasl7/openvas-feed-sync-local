# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:openview_network_node_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900211");
  script_version("2025-04-11T15:45:04+0000");
  script_cve_id("CVE-2008-3536", "CVE-2008-3537", "CVE-2008-3544");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2008-09-05 16:50:44 +0200 (Fri, 05 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("HP OpenView Network Node Manager Multiple DoS Vulnerabilities (HPSBMA02362)");
  script_dependencies("secpod_hp_openview_nnm_detect.nasl");
  script_mandatory_keys("HP/OVNNM/installed");

  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-c01537275");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31688/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30984");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2485");

  script_tag(name:"summary", value:"HP OpenView Network Node Manager (OV NNM) is prone to multiple
  denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to an error in ovalarmsrv program.");

  script_tag(name:"impact", value:"Successful exploitation can cause application to crash.");

  script_tag(name:"affected", value:"HP OV NNM versions 7.01, 7.51 and 7.53 are known to be
  affected.");

  script_tag(name:"solution", value:"Apply the updates from the referenced vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ! vers = get_kb_item( "www/" + port + "/HP/OVNNM/Ver" ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"B.07.01" ) ||
    version_is_equal( version:vers, test_version:"B.07.51" ) ||
    version_is_equal( version:vers, test_version:"B.07.53" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
