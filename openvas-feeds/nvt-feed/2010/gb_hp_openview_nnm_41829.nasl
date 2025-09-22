# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:openview_network_node_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100786");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2703");
  script_name("HP OpenView Network Node Manager 'execvp_nc()' Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("os_detection.nasl", "secpod_hp_openview_nnm_detect.nasl");
  script_mandatory_keys("HP/OVNNM/installed", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41829");
  script_xref(name:"URL", value:"http://www.exploit-db.com/moaub-6-hp-openview-nnm-webappmon-exe-execvp_nc-remote-code-execution/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/512543");
  script_xref(name:"URL", value:"http://itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02286088");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-137/");

  script_tag(name:"summary", value:"HP OpenView Network Node Manager (OV NNM) is prone to a remote
  code-execution vulnerability.");
  script_tag(name:"affected", value:"The issue affects HP OpenView Network Node Manager versions 7.51 and
  7.53 running on the Windows platform.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with SYSTEM-
  level privileges. Successful exploits will completely compromise
  affected computers.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_version( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! vers = get_kb_item( "www/"+ port + "/HP/OVNNM/Ver" ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"B.07.51" ) ||
    version_is_equal( version:vers, test_version:"B.07.53" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
