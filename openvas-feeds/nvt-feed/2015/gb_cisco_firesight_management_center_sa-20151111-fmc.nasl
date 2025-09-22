# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:firesight_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105455");
  script_cve_id("CVE-2015-6363");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Cisco FireSight Management Center Web Framework Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151111-fmc");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by injecting malicious code into an affected parameter and then persuading a user to access a web page that triggers execution of the injected code.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to improper sanitization of parameter values.");

  script_tag(name:"solution", value:"See vendor advisory");
  script_tag(name:"summary", value:"A vulnerability in the web framework of Cisco FireSIGHT Management Center (MC) could allow an authenticated, remote attacker to execute a stored, cross-site scripting (XSS) attack against a user of the web interface.");
  script_tag(name:"affected", value:"Cisco FireSIGHT Management Center versions 5.4.1.4 and 6.0.1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-16 16:14:53 +0100 (Mon, 16 Nov 2015)");
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

if( version == "6.0.1" || version == '5.4.1.4' )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     See vendor advisory';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

