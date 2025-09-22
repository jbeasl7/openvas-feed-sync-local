# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100369");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-12-01 12:01:39 +0100 (Tue, 01 Dec 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 16:04:42 +0000 (Fri, 02 Feb 2024)");

  script_cve_id("CVE-2009-3553");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("CUPS 1.3.7 File Descriptors Handling Remote DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"CUPS is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A remote attacker can exploit this issue to crash the affected
  application, denying service to legitimate users.");

  script_tag(name:"affected", value:"CUPS version 1.3.7. Other versions may be vulnerable
  as well.");

  script_tag(name:"solution", value:"Update to version 1.3.8 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37048");
  script_xref(name:"URL", value:"http://www.cups.org");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530111");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+") exit( 0 ); # Version is not exact enough

if( version_is_equal( version:vers, test_version:"1.3.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.8" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
