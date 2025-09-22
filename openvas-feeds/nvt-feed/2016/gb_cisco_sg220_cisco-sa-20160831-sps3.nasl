# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106241");
  script_version("2025-03-14T15:40:32+0000");
  script_tag(name:"last_modification", value:"2025-03-14 15:40:32 +0000 (Fri, 14 Mar 2025)");
  script_tag(name:"creation_date", value:"2016-09-13 10:45:09 +0700 (Tue, 13 Sep 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)");
  script_cve_id("CVE-1999-0517", "CVE-2016-1473");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Small Business 220 Series Smart Plus Switches SNMP Unauthorized Access Vulnerability (cisco-sa-20160831-sps3)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("snmp_detect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/detected");

  script_tag(name:"summary", value:"A vulnerability in the implementation of SNMP functionality in Cisco
  Small Business 220 Series Smart Plus (Sx220) Switches could allow an unauthenticated, remote attacker to
  gain unauthorized access to SNMP objects on an affected device.");

  script_tag(name:"vuldetect", value:"Tries to get the SNMP system description with the default community.");

  script_tag(name:"insight", value:"The vulnerability is due to the presence of a default SNMP community
  string that is added during device installation and cannot be deleted. An attacker could exploit this
  vulnerability by using the default SNMP community string to access SNMP objects on an affected device.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to view and modify SNMP
  objects on a targeted device.");

  script_tag(name:"affected", value:"Cisco Small Business 220 Series Smart Plus (Sx220) Switches running
  firmware release 1.0.0.17, 1.0.0.18, or 1.0.0.19.");

  script_tag(name:"solution", value:"Upgrade to firmware release 1.0.1.1.");

  script_xref(name:"URL", value:"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160831-sps3");
  script_xref(name:"URL", value:"http://www.synacktiv.ninja/ressources/advisories_cisco_switch_sg220_default_snmp.pdf");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default:161 );
if( get_kb_item( "SNMP/" + port + "/v12c/all_communities" ) ) exit( 0 ); # For devices which are accepting every random community

community = "rmonmgmtuicommunity";

if (res = snmp_get(port: port, oid: '1.3.6.1.2.1.1.1.0', version: 2, community: community)) {
  report = "Result of the system description query with the community 'rmonmgmtuicommunity':\n\n" + res + "\n";
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
