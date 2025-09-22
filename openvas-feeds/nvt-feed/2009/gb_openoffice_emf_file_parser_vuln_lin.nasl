# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openoffice:openoffice.org";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901019");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2139");
  script_name("OpenOffice.org < 3.1.1 EMF File Parser RCE Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openoffice_ssh_login_detect.nasl");
  script_mandatory_keys("openoffice.org/linux/detected");

  script_xref(name:"URL", value:"http://www.debian.org/security/2009/dsa-1880");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36291");

  script_tag(name:"summary", value:"OpenOffice.org is prone to a remote command execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An Unspecified error occurs in the parser of EMF files when
  parsing certain crafted EMF files.");

  script_tag(name:"impact", value:"Successful remote exploitation could result in arbitrary code
  execution.");

  script_tag(name:"affected", value:"OpenOffice.org versions prior to 3.1.1.");

  script_tag(name:"solution", value:"Update to version 3.1.1 or later.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"3.1.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.1.1" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
