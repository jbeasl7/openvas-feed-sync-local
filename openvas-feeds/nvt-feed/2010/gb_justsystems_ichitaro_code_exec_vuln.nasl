# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800794");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2152");
  script_name("JustSystems Ichitaro 2004 - 2009 'character attribute' Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_justsystems_ichitaro_prdts_detect.nasl");
  script_mandatory_keys("Ichitaro/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40472");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN17293765/index.html");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1283");
  script_xref(name:"URL", value:"http://www.justsystems.com/jp/info/js10002.html");

  script_tag(name:"summary", value:"JustSystems Ichitaro is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to unspecified memory corruption error when
  processing 'character attributes'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to corrupt memory to
  execute arbitrary code on the system.");

  script_tag(name:"affected", value:"JustSystems Ichitaro 2004 through 2009.");

  script_tag(name:"solution", value:"Apply the patch available in the referenced vendor advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

CPE = "cpe:/a:ichitaro:ichitaro";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! vers = get_app_version( cpe: CPE ) )
  exit( 0 );

if( version_in_range( version: vers, test_version: "2004", test_version2: "2009" ) ) {
  report = report_fixed_ver( installed_version: vers, vulnerable_range:"2004 - 2009", fixed_version: "Apply the referenced patch" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
