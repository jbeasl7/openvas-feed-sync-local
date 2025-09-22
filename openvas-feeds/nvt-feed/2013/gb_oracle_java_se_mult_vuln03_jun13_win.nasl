# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803821");
  script_version("2024-02-16T05:06:55+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-2473", "CVE-2013-2472", "CVE-2013-2471", "CVE-2013-2470",
                "CVE-2013-2469", "CVE-2013-2465", "CVE-2013-2464", "CVE-2013-2463",
                "CVE-2013-2459", "CVE-2013-2457", "CVE-2013-2456", "CVE-2013-2455",
                "CVE-2013-2454", "CVE-2013-2452", "CVE-2013-2450", "CVE-2013-2448",
                "CVE-2013-2447", "CVE-2013-2446", "CVE-2013-2445", "CVE-2013-2443",
                "CVE-2013-1500", "CVE-2013-1571");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-06-24 17:10:36 +0530 (Mon, 24 Jun 2013)");
  script_name("Oracle Java SE Multiple Vulnerabilities -03 (Jun 2013) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpujun2013-1899847.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60617");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60619");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60620");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60623");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60627");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60629");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60631");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60632");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60634");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60638");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60639");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60640");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60641");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60646");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60647");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60650");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60651");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60655");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60656");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60657");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60658");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60659");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/javacpujun2013verbose-1899853.html");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors. Attackers can even execute arbitrary code on the target system.");

  script_tag(name:"affected", value:"Oracle Java SE Version 7 Update 21 and earlier, 6 Update 45 and earlier,
  and 5.0 Update 45 and earlier.");

  script_tag(name:"insight", value:"Multiple flaws are due to unspecified errors in the 2D, AWT, JMX, JDBC, CORBA,
  serialization, libraries, Sound, Networking, Hotspot and Javadoc components.");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Update to Java SE Version 7 Update 25 or later.");

  script_tag(name:"qod_type", value:"registry");
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

if( version_in_range( version: vers, test_version: "1.7", test_version2: "1.7.0.21" ) ||
    version_in_range( version: vers, test_version: "1.6", test_version2: "1.6.0.45" ) ||
    version_in_range( version: vers, test_version: "1.5", test_version2: "1.5.0.45" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "Java SE Version 7 Update 25", install_path: path );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
