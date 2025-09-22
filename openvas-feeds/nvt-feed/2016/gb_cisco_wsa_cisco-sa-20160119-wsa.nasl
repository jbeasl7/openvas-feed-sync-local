# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105523");
  script_cve_id("CVE-2016-1296");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco Web Security Appliance Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160119-wsa");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by crafting an improper HTTP method. A successful exploit could allow the attacker to circumvent WSA functionality that prevents proxied network traffic.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to improper handling of malformed HTTP methods.");
  script_tag(name:"solution", value:"Cisco released software updates that address this vulnerability.");
  script_tag(name:"summary", value:"A vulnerability in the proxy engine of the Cisco Web Security Appliance (WSA) could allow an unauthenticated, remote attacker to bypass security restrictions.");

  script_tag(name:"affected", value:"See Vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 23:38:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-01-20 12:21:34 +0100 (Wed, 20 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/installed");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version == "8.5.3-055" || version == "9.1.0-000" || version == '9.5.0-235' )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     See vendor advisory';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

