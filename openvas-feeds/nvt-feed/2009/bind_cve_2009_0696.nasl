# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100251");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 21:36:35 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0696");
  script_name("ISC BIND Remote Dynamic Update Message DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35848");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=514292");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=538975");
  script_xref(name:"URL", value:"https://kb.isc.org/docs/aa-00926");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/725188");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows remote attackers to crash
  affected DNS servers, denying further service to legitimate users.");

  script_tag(name:"affected", value:"Versions prior to BIND 9.4.3-P3, 9.5.1-P3, and 9.6.1-P1 are
  vulnerable.");

  script_tag(name:"solution", value:"The vendor released an advisory and fixes to address this issue.
  Please see the references for more information.");

  script_tag(name:"summary", value:"ISC BIND is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"insight", value:"The flaw exists because the application fails to properly handle
  specially crafted dynamic update requests.");

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

if( version_in_range( version:version, test_version:"9.6", test_version2:"9.6.1" ) ||
    version_in_range( version:version, test_version:"9.5", test_version2:"9.5.1p2") ||
    version_in_range( version:version, test_version:"9.0", test_version2:"9.4.3p2" ) ) {

  report = report_fixed_ver( installed_version:version, fixed_version:"See advisory", install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
