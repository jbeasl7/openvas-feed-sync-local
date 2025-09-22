# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103925");
  script_cve_id("CVE-2014-2205");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_version("2025-01-21T05:37:33+0000");

  script_name("McAfee ePolicy Orchestrator < 4.6.7 Hotfix 940148 XXE Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65771");

  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2014-03-20 11:41:18 +0100 (Thu, 20 Mar 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain access to sensitive
  information from the application. This may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Import and Export Framework in McAfee ePolicy Orchestrator
  (ePO) before 4.6.7 Hotfix 940148 allows remote authenticated users with permissions to add
  dashboards to read arbitrary files by importing a crafted XML file, related to an XML External
  Entity (XXE) issue.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"McAfee ePolicy Orchestrator is prone to an XML external entity
  (XXE) vulnerability.");

  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator versions 4.6.7 and prior are
  vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port(cpe:CPE) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"4.6.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.6.7" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
