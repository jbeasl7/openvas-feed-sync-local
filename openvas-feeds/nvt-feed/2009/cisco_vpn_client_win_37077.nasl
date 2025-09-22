# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100357");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-20 12:35:38 +0100 (Fri, 20 Nov 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4118");
  script_name("Cisco VPN Client for Windows 'StartServiceCtrlDispatche' Local Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("cisco_vpn_client_detect.nasl");
  script_mandatory_keys("SMB/CiscoVPNClient/Version");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37077");
  script_xref(name:"URL", value:"http://www.cisco.com/warp/public/cc/pd/sqsw/vpncl/index.shtml");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=19445");

  script_tag(name:"summary", value:"Cisco VPN Client for Windows is prone to a local denial-of-service
  vulnerability.");
  script_tag(name:"impact", value:"A local attacker can exploit this issue to crash the application,
  resulting in a denial-of-service condition.");
  script_tag(name:"affected", value:"This issue affects Cisco VPN Client for Windows versions prior
  5.0.06.0100.");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("version_func.inc");

if( ! version = get_kb_item( "SMB/CiscoVPNClient/Version" ) ) exit( 0 );

if( version_is_less( version:version, test_version:"5.0.06.0100" ) ) {
  report = report_fixed_ver(installed_version:version, fixed_version:"5.0.06.0100");
  security_message(port: 0, data: report);
  exit( 0 );
}

exit( 99 );
