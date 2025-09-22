# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113138");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-03-20 10:20:20 +0100 (Tue, 20 Mar 2018)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-10 18:21:00 +0000 (Tue, 10 Apr 2018)");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-6321", "CVE-2018-6322");

  script_name("Panda Global Protection <= 17.0.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_panda_prdts_detect.nasl");
  script_mandatory_keys("Panda/GlobalProtection/Ver");

  script_tag(name:"summary", value:"Panda Global Protection is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  Unquoted Windows search path vulnerability in the panda_url_filtering service in Panda Global Protection allows
  local users to gain privileges via a malicious artifact.

  Panda Global Protection allows local users to gain privileges or cause a denial of service by impersonating all
  the pipes through a use of \.\pipe\PSANMSrvcPpal -- an 'insecurely created named pipe'. Ensures full access to
  Everyone users group.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain complete control over
  the target system.");

  script_tag(name:"affected", value:"Panda Global Protection through version 17.0.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Mar/25");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2018/Mar/26");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

cpe_list = make_list( "cpe:/a:pandasecurity:panda_global_protection_2010",
                      "cpe:/a:pandasecurity:panda_global_protection_2014" );

if( ! infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version: vers, test_version: "17.00.01" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 0 );
