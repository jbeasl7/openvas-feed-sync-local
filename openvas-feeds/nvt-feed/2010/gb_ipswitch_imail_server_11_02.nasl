# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ipswitch:imail_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100718");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-07-16 12:38:11 +0200 (Fri, 16 Jul 2010)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");
  script_name("Ipswitch IMail Server < 11.02 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_ipswitch_imail_server_detect.nasl");
  script_mandatory_keys("Ipswitch/IMail/detected");

  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-10-127/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210127200042/https://www.securityfocus.com/bid/41719/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210509083350/http://www.securityfocus.com/bid/41718");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210509063658/http://www.securityfocus.com/bid/41717");

  script_tag(name:"summary", value:"Ipswitch IMail Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Multiple buffer-overflow vulnerabilities because it fails to perform adequate boundary checks on
  user supplied data

  - Multiple remote code execution (RCE) vulnerabilities");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code
  with SYSTEM-level privileges. Successfully exploiting these issues will result in the complete
  compromise of affected computers. Failed exploit attempts will result in a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Ipswitch IMail Server versions prior to 11.02.");

  script_tag(name:"solution", value:"Vendor updates are available. Please contact the vendor for more
  information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"11.02" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.02" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
