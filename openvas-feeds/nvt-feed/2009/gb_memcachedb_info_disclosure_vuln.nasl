# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:memcachedb:memcached";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800717");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-1255");
  script_name("MemcacheDB Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_memcachedb_detect.nasl");
  script_mandatory_keys("MemcacheDB/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34932");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34756");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1197");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft execute
  malicious commands and pass it to the vulnerable functions to gain sensitive
  information about the application.");

  script_tag(name:"affected", value:"MemcacheDB version 1.2.0 and prior.");

  script_tag(name:"insight", value:"Error in process_stat function discloses the contents of
  /proc/self/maps in response to a stats maps command.");

  script_tag(name:"summary", value:"MemcacheDB is prone to Information Disclosure Vulnerabilities.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit(0);

if( version_is_less_equal( version:vers, test_version:"1.2.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );