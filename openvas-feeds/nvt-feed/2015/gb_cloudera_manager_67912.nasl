# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cloudera:cloudera_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105174");
  script_cve_id("CVE-2014-0220");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_version("2025-01-17T15:39:18+0000");

  script_name("Cloudera Manager < 4.8.3 Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67912");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that
  may aid in launching further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cloudera Manager allows remote authenticated users to obtain sensitive configuration information
  via the API.");

  script_tag(name:"solution", value:"Update Cloudera Manager to version 4.8.3/5.0.1 or later.");

  script_tag(name:"summary", value:"Cloudera Manager is prone to an information disclosure vulnerability.");

  script_tag(name:"affected", value:"Cloudera Manager prior to 4.8.3 and 5.0.0 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-01-20 17:01:26 +0100 (Tue, 20 Jan 2015)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cloudera_manager_detect.nasl");
  script_mandatory_keys("cloudera_manager/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"4.8.3" ) ) {
  fix = "4.8.3";
  VULN = TRUE;
}

else if( vers =~ "^5\." ) {
  if( version_is_less( version:vers, test_version:'5.0.1') ) {
    fix = "5.0.1";
    VULN = TRUE;
  }
}

if( VULN ) {
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + fix  + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
