# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800338");
  script_version("2024-02-14T05:07:39+0000");
  script_tag(name:"last_modification", value:"2024-02-14 05:07:39 +0000 (Wed, 14 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 17:43:48 +0000 (Tue, 13 Feb 2024)");
  script_cve_id("CVE-2008-5077", "CVE-2009-0025", "CVE-2009-0265");
  script_name("ISC BIND OpenSSL DSA_verify() Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");

  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-00925");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33150");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33151");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33404/");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2008-016.html");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to bypass the certificate
  validation checks and can cause man-in-the-middle attack via signature checks on DSA and ECDSA keys used with SSL/TLS.");

  script_tag(name:"affected", value:"ISC BIND versions prior to 9.2 or 9.6.0 P1 or 9.5.1 P1 or 9.4.3 P1 or 9.3.6 P1.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of return value from OpenSSL's
  DSA_do_verify and VP_VerifyFinal functions.");

  script_tag(name:"solution", value:"Update to version 9.6.0 P1, 9.5.1 P1, 9.4.3 P1, 9.3.6 P1.");

  script_tag(name:"summary", value:"ISC BIND is prone to a security bypass vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if( version_in_range( version:version, test_version:"9.6", test_version2:"9.6.0" ) ||
    version_in_range( version:version, test_version:"9.5", test_version2:"9.5.1" ) ||
    version_in_range( version:version, test_version:"9.4", test_version2:"9.4.3" ) ||
    version_in_range( version:version, test_version:"9.3", test_version2:"9.3.6" ) ||
    version_is_less( version:version, test_version:"9.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"9.6.0 P1, 9.5.1 P1, 9.4.3 P1 or 9.3.6 P1", install_path:location );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
