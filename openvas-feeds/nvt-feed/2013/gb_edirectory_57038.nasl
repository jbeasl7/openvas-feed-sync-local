# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netiq:edirectory";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103630");
  script_version("2024-09-16T09:36:54+0000");
  script_tag(name:"last_modification", value:"2024-09-16 09:36:54 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"creation_date", value:"2013-01-02 11:38:11 +0100 (Wed, 02 Jan 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2012-0428", "CVE-2012-0429", "CVE-2012-0430", "CVE-2012-0432");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell eDirectory Multiple Vulnerabilities (Jan 2013)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_netiq_edirectory_ldap_detect.nasl");
  script_mandatory_keys("netiq/edirectory/detected");

  script_tag(name:"summary", value:"Novell eDirectory is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Cross-site scripting (XSS)

  - Denial of service (DoS)

  - Information disclosure

  - Stack-based buffer overflow");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site,
  steal cookie-based authentication credentials, disclose sensitive information, execute arbitrary
  code, cause a denial of service condition. Other attacks are possible.");

  script_tag(name:"affected", value:"Novell eDirectory prior to version 8.8.7.2 or 8.8.6.7.");

  script_tag(name:"solution", value:"Update to version 8.8.6.7, 8.8.7.2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57038");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! major = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ! sp = get_kb_item( "netiq/edirectory/" + port + "/sp" ) )
  sp = "0";

revision = get_kb_item( "netiq/edirectory/" + port + "/build" );
revision = str_replace( string:revision, find:".", replace:"" );

instvers = major;

if( sp > 0 )
  instvers += " SP" + sp;

if( major =~ "^8\.8" ) {
  if( ! sp || sp < 6 )
    vuln = TRUE;

  if( sp == 6 && ( ! revision || revision < 20608 ) )
    vuln = TRUE;

  if( sp == 7 && ( ! revision || revision < 20703 ) )
    vuln = TRUE;
}

if( vuln ) {
  report = report_fixed_ver( installed_version:instvers, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit(0);
}

exit(99);
