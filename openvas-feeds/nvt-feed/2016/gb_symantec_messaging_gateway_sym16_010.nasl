# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:messaging_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105783");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2016-06-29 15:43:27 +0200 (Wed, 29 Jun 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-11 19:23:00 +0000 (Mon, 11 May 2020)");

  script_cve_id("CVE-2016-2207", "CVE-2016-2209", "CVE-2016-2210", "CVE-2016-2211",
                "CVE-2016-3644", "CVE-2016-3645", "CVE-2016-3646");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Symantec Messaging Gateway Decomposer Engine Multiple Parsing Vulnerabilities (SYM16-010)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symantec_messaging_gateway_consolidation.nasl");
  script_mandatory_keys("symantec/smg/detected");

  script_tag(name:"summary", value:"Parsing of maliciously-formatted container files may cause
  memory corruption, integer overflow or buffer overflow in Symantecs Decomposer engine.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"In the TNEF unpacker, the overflow does not result in any
  detrimental actions due to underlying code. However this was an exposure due to improper
  implementation that could potentially be leveraged further, at some point, by a malicious
  individual. As such, it also was addressed in the engine update.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities typically
  results in an application-level denial of service but could result in arbitrary code execution.
  An attacker could potentially run arbitrary code by sending a specially crafted file to a
  user.");

  script_tag(name:"affected", value:"Symantec Messaging Gateway version 10.6.1-3 and prior.");

  script_tag(name:"solution", value:"Update to version 10.6.1-4 or later.");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"10.6.1" ) )
  vuln = TRUE;

patch = get_kb_item( "symantec/smg/patch" );

if( version == "10.6.1" ) {
  if( patch ) {
    if( int( patch ) < 4 )
      vuln = TRUE;
  } else
    vuln = TRUE;
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, installed_patch:patch,
                             fixed_version:"10.6.1", fixed_patch:"4" );
  security_message( port:0, data:report );
  exit(0);
}

exit( 99 );
