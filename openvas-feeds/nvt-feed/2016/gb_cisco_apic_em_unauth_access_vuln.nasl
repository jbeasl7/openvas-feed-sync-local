# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:application_policy_infrastructure_controller_enterprise_module";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807836");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2016-1386");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:20:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-06-13 15:58:36 +0530 (Mon, 13 Jun 2016)");
  script_name("Cisco APIC Enterprise Module Unauthorized Access Vulnerability (cisco-sa-20160428-apic)");

  script_tag(name:"summary", value:"Cisco APIC Enterprise Module is prone to unauthorized access vulnerability.");

  script_tag(name:"vuldetect", value:"Check for the vulnerable version of Cisco
  APIC Enterprise Module.");

  script_tag(name:"insight", value:"The error exists due to insufficient protection
  of API functions, which does not handle modified attribute-value pairs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create false system notifications for administrators and trick the
  administrative users into performing a malicious task on behalf of the attacker.");

  script_tag(name:"affected", value:"Cisco APIC-EM version 1.0(1) is affected.");

  script_tag(name:"solution", value:"Apply the updates from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # advisory is very vague about effected versions

  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux15521");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160428-apic");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_dependencies("gb_cisco_apic_em_web_detect.nasl");
  script_mandatory_keys("cisco/apic_em/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^1\.0\(1\)") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"See vendor advisory");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
