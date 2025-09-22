# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:ucs_central_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105574");
  script_cve_id("CVE-2015-6388", "CVE-2015-6387");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("2023-07-20T05:05:17+0000");

  script_name("Cisco UCS Central Software Server Side Request Forgery Security Bypass / Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151201-ucs");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/78420");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151201-ucs1");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass certain security restrictions to perform unauthorized actions. This may aid in further attacks.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to improper validation of user-supplied input on the affected system.");
  script_tag(name:"solution", value:"Upgrade to UCS Central 1.4 Release");
  script_tag(name:"summary", value:"A vulnerability in the Cisco Unified Computing System (UCS) Central software could allow an unauthenticated, remote attacker to bypass access controls and conduct a server-side request forgery (SSRF) or cross-site scripting (XSS) on a targeted system.");
  script_tag(name:"affected", value:"1.3(0.1)");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-17 14:20:49 +0100 (Thu, 17 Mar 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ucs_central_version.nasl");
  script_mandatory_keys("cisco_ucs_central/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# example: 1.4(1a).
if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ '^1\\.3' )
{
  report = report_fixed_ver(  installed_version:version, fixed_version:"1.4(1a)" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

