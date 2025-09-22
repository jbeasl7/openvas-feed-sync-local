# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firesight_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105484");
  script_cve_id("CVE-2015-6419");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_version("2025-01-21T05:37:33+0000");

  script_name("Cisco FireSIGHT Management Center GET Request Information Disclosure Vulnerability (cisco-sa-20151211-fmc)");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151211-fmc");

  script_tag(name:"impact", value:"Disclosure of sensitive information from the underlying operating system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper sanitation of user-supplied input. An attacker could exploit this vulnerability by sending special GET requests to a vulnerable device.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");
  script_tag(name:"summary", value:"A vulnerability in the Cisco FireSIGHT Management Center could allow an authenticated, remote attacker to view sensitive information from the underlying operating system.");
  script_tag(name:"affected", value:"Cisco FireSIGHT Management Center running FireSIGHT System Software releases 4.10.3, 5.2.0, 5.3.0, 5.3.1, and 5.4.0 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-12-15 10:41:43 +0100 (Tue, 15 Dec 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_firesight_management_center_version.nasl",
                      "gb_cisco_firesight_management_center_http_detect.nasl");
  script_mandatory_keys("cisco_firesight_management_center/version");
  exit(0);
}

include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

vulnerable = make_list( "4.10.3", "5.2.0", "5.3.0", "5.3.1", "5.4.0" );

foreach v ( vulnerable )
{
  if( version == v )
  {
    VULN = TRUE;
    break;
  }
}

if( VULN )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     See vendor advisory';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
