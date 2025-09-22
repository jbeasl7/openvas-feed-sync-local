# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105473");
  script_cve_id("CVE-2015-6386");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco Web Security Appliance Native FTP Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151130-wsa");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability occurs when the FTP client terminates the FTP control connection when the data transfer is complete. An attacker could exploit this vulnerability by initiating FTP connections through the WSA. An exploit could allow the attacker to cause high CPU utilization of the Cisco WSA proxy process, causing a partial DoS condition. The attacker's choice of FTP client and how that client closes the FTP control connection will affect the attacker's ability to exploit this vulnerability.");
  script_tag(name:"solution", value:"See Vendor advisory.");
  script_tag(name:"summary", value:"A vulnerability in the native passthrough FTP functionality of the Cisco Web Security Appliance (WSA) could allow an unauthenticated, remote attacker to cause a partial denial of service (DoS) condition due to high CPU utilization.");

  script_tag(name:"affected", value:"See Vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-01 16:10:38 +0100 (Tue, 01 Dec 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/installed");

  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version == "8.0.7-142" || version == "8.5.1-021" || version == '8.5.2-027' )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     See vendor advisory';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

