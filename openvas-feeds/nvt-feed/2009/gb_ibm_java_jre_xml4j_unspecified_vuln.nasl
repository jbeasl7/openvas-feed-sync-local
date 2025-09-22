# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800974");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-09 14:01:44 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3852");
  script_name("IBM Runtimes for Java Technology XML4J Unspecified Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("IBM/Java/JRE/Linux/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54069");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36894");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3106");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg1IZ63920");

  script_tag(name:"affected", value:"IBM Runtimes for Java Technology 5.0.0 before SR10 on Linux.");

  script_tag(name:"insight", value:"An unspecified error occurs in the 'XML4J' component while parsing XML
  code.");

  script_tag(name:"summary", value:"IBM Runtime for Java Technology is prone to an unspecified vulnerability.");

  script_tag(name:"solution", value:"Apply the referenced vendor update.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

cpe_list = make_list( "cpe:/a:sun:jre", "cpe:/a:oracle:jre" );

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version: vers, test_version: "1.5", test_version2: "1.5.0.SR9" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "1.5.0.SR10", install_path: path );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
