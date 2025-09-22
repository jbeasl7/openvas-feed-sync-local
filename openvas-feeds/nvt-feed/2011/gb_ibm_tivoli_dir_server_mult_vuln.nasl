# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802224");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2758", "CVE-2011-2759");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("IBM Tivoli Directory Server Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_ibm_tivoli_dir_server_detect.nasl");
  script_mandatory_keys("IBM/TDS/Ver");

  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg24030320");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48512");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain sensitive information
  that may aid in further attacks.");

  script_tag(name:"affected", value:"IBM Tivoli Directory Server (TDS) 6.2 before 6.2.0.3-TIV-ITDS-IF0004");

  script_tag(name:"insight", value:"- IDSWebApp in the Web Administration Tool not restricting access to LDAP
  Server log files, which allows remote attackers to obtain sensitive information via a crafted URL.

  - The login page of IDSWebApp in the Web Administration Tool does not have
  an off autocomplete attribute for authentication fields, which makes it
  easier for remote attackers to obtain access by leveraging an unattended workstation.");

  script_tag(name:"summary", value:"IBM Tivoli Directory Server is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Apply cumulative interim fix 6.2.0.3-TIV-ITDS-IF0004.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:ibm:tivoli_directory_server";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE ) ) exit( 0 );

if( version_in_range( version: version, test_version: "6.20", test_version2: "6.20.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "6.20.0.3" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
