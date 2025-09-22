# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:netiq:edirectory";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800731");
  script_version("2024-09-16T09:36:54+0000");
  script_tag(name:"last_modification", value:"2024-09-16 09:36:54 +0000 (Mon, 16 Sep 2024)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-4655");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Novell eDirectory <= 8.8.5 Cookie Hijack Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_netiq_edirectory_ldap_detect.nasl");
  script_mandatory_keys("netiq/edirectory/detected");

  script_tag(name:"summary", value:"Novell eDirectory is prone to a session cookie hijack
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in an 'DHOST' module when handling
  DHOST web services. An attacker would wait until the real administrator logs in, then specify the
  predicted cookie value to hijack their session.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to hijack
  arbitrary sessions.");

  script_tag(name:"affected", value:"Novell eDirectory version 8.8.5 and prior.");

  script_tag(name:"solution", value:"Apply the vendor provided patch.");

  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=3426981");
  script_xref(name:"URL", value:"http://www.metasploit.com/modules/auxiliary/admin/edirectory/edirectory_dhost_cookie");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! major = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ! sp = get_kb_item( "netiq/edirectory/" + port + "/sp" ) )
  sp = "0";

reportver = major;

if( sp > 0 )
  reportver += " SP" + sp;

version = major + "." + sp;

if( version_in_range( version:version, test_version:"8.8", test_version2:"8.8.5" ) ) {
  report = report_fixed_ver( installed_version:reportver, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
