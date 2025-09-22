# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:ip_interoperability_and_collaboration_system";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105603");
  script_cve_id("CVE-2016-1375");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-07-21T05:05:22+0000");

  script_name("Cisco IP Interoperability and Collaboration System Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160407-cic");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy12339");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy12340");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by persuading a user of an
  affected system to follow a malicious link.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to insufficient XSS protections.");
  script_tag(name:"solution", value:"Update to version 5.0(1) or later. Please see the references for more information.");
  script_tag(name:"summary", value:"A vulnerability in the web framework code of Cisco IP Interoperability and Collaboration
  System could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-14 00:44:00 +0000 (Thu, 14 Apr 2016)");
  script_tag(name:"creation_date", value:"2016-04-11 14:05:33 +0200 (Mon, 11 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ipics_version.nasl");
  script_mandatory_keys("cisco/ipics/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version == '4.10(1)' )
{
  report = report_fixed_ver(  installed_version:version, fixed_version:'5.0(1)' );
  security_message( port:0, data:report);
  exit( 0 );
}

exit( 99 );