# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vtiger:vtiger_crm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103973");
  script_cve_id("CVE-2013-3214");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2025-05-09T15:42:11+0000");
  script_tag(name:"last_modification", value:"2025-05-09 15:42:11 +0000 (Fri, 09 May 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 19:07:00 +0000 (Fri, 31 Jan 2020)");
  script_tag(name:"creation_date", value:"2014-01-30 12:15:25 +0700 (Thu, 30 Jan 2014)");

  script_name("vTiger CRM PHP Code Injection Vulnerability");

  script_xref(name:"URL", value:"https://www.vtiger.com/blogs/?p=1467");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61558");
  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2013-07");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_vtiger_crm_detect.nasl");
  script_mandatory_keys("vtiger/detected");

  script_tag(name:"summary", value:"vTiger CRM PHP Code Injection Vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Apply the patch from the link below or upgrade to version
  6.0 or later.");

  script_tag(name:"insight", value:"The installed vTiger CRM is prone to a PHP code injection
  vulnerability. The AddEmailAttachment SOAP method in /soap/vtigerolservice.php
  fails to properly validate input passed through the 'filedata' and 'filename'
  parameters which are used to write an 'email attachement' in the storage directory.");

  script_tag(name:"affected", value:"vTiger CRM version 5.0.0 to 5.4.0.");

  script_tag(name:"impact", value:"A remote attacker can write (or overwrite) files with any content,
  resulting in execution of arbitrary PHP code.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port(cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"5.0.0", test_version2:"5.4.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
