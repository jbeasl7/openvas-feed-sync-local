# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:qradar_security_information_and_event_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105803");
  script_version("2024-11-08T15:39:48+0000");
  script_cve_id("CVE-2016-2868", "CVE-2016-2968", "CVE-2016-2872");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-11-08 15:39:48 +0000 (Fri, 08 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-06 23:40:00 +0000 (Wed, 06 Jul 2016)");
  script_tag(name:"creation_date", value:"2016-07-07 17:08:10 +0200 (Thu, 07 Jul 2016)");
  script_name("IBM QRadar Multiple Vulnerabilities (282855, 282857, 282859)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_ibm_qradar_siem_consolidation.nasl");
  script_mandatory_keys("ibm/qradar/siem/detected");

  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/node/282859");
  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/node/282857");
  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/node/282855");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91377");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91373");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91372");

  script_tag(name:"summary", value:"IBM QRadar is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"IBM QRadar could allow a remote attacker with administrator
  privileges to obtain sensitive information, caused by an error when processing XML external
  entities. By sending specially-crafted XML data, an attacker could exploit this vulnerability to
  obtain sensitive information.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain access to sensitive
  information that may lead to further attacks.");

  script_tag(name:"affected", value:"IBM QRadar versions 7.2.x prior to 7.2.7.");

  script_tag(name:"solution", value:"Update to version 7.2.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

if( version_in_range( version:version, test_version:"7.2", test_version2:"7.2.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.2.7" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
