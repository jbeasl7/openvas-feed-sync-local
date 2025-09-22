# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105444");
  script_cve_id("CVE-2015-4184");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Email Security Appliance Anti-Spam Scanner Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=39339");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper handling of a malformed packet in the anti-spam scanner. An attacker could exploit this vulnerability by sending a crafted
DNS Sender Policy Framework (SPF) text record. An exploit could allow the attacker to bypass the anti-spam scanner and generate a malformed packet alert.");

  script_tag(name:"solution", value:"See Vendor advisory.");
  script_tag(name:"summary", value:"Cisco Email Security Appliance contains a vulnerability that could allow an unauthenticated, remote attacker to bypass security restrictions.");

  script_tag(name:"affected", value:"See Vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-10 11:01:51 +0100 (Tue, 10 Nov 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version == '7.6.1-gpl-022' || version == '8.5.6-074' || version == '3.3.1-09' )
{
  fix = "See Vendor advisory.";
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     ' + fix + '\n';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

