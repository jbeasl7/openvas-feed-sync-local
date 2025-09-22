# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806529");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2015-0578");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-11-20 12:27:12 +0530 (Fri, 20 Nov 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("Cisco ASA Software DHCPv6 Relay DoS Vulnerability (cisco-sa-20150115-asa-dhcp)");

  script_tag(name:"summary", value:"Cisco ASA Software is prone to a denial of service (DoS) vulnerability.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.106053.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient validation
  of crafted DHCP packets. Cisco ASA Software is affected by this vulnerability
  only when configured as a DHCP version 6 relay.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated, remote attacker to cause an affected device to reload,
  resulting in a denial of service condition.");

  script_tag(name:"affected", value:"Cisco ASA Software versions 7.2 before
  8.2(5.58), 8.3 before 8.4(7.29), 8.5 before 9.0(4.37), 8.7 before 8.7(1.17),
  9.0 before 9.0(4.37), 9.1 before 9.1(6.8), 9.2 before 9.2(4), 9.3 before
  9.3(3.5), 9.4 before 9.4(2).");

  script_tag(name:"solution", value:"Update to 8.2(5.58) or 8.4(7.29) or
  9.0(4.37) or 8.7(1.17) or 9.0(4.37) or 9.1(6.8) or 9.2(4) or 9.3(3.5) or
  9.4(2) or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031542");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/72718");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=37022");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150115-asa-dhcp");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CISCO");

  exit(0);
}

exit(66); ## This VT is deprecated as addressed in gb_cisco_asa_CSCur45455.nasl(1.3.6.1.4.1.25623.1.0.106053).
