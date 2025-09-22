# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:meeting_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809734");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-1451");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-18 15:08:00 +0000 (Mon, 18 Jul 2016)");
  script_tag(name:"creation_date", value:"2016-11-26 19:19:29 +0530 (Sat, 26 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cisco Meeting Server Cross-Site Scripting Vulnerability (cisco-sa-20160714-ms)");

  script_tag(name:"summary", value:"Cisco Meeting Server is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in validation of
  certain parameters that are passed to an affected device via an HTTP request.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary script code in the context of the affected
  management interface or allow the attacker to access sensitive browser-based
  information.");

  script_tag(name:"affected", value:"Cisco Meeting Server 1.7.x prior to 1.7.24,
  1.8.x prior to 1.8.15 and 1.9.x prior to 1.9.2");

  script_tag(name:"solution", value:"Upgrade to Cisco Meeting Server 1.7.24 or
  1.8.15 or 1.9.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva19922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91784");
  script_xref(name:"URL", value:"https://listserv.uni-hohenheim.de/pipermail/sec-cert/2016-August/022182.html");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160714-ms");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CISCO");
  script_dependencies("gb_cisco_meeting_server_snmp_detect.nasl");
  script_mandatory_keys("cisco/meeting_server/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");


if(!cisPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!version = get_app_version(cpe:CPE, port:cisPort)){
  exit(0);
}

if(version =~ "^(1\.(7|8|9))")
{
  if(version_in_range(version:version, test_version:"1.7", test_version2:"1.7.23"))
  {
    VULN = TRUE;
    fix = "1.7.24";
  }

  else if(version_in_range(version:version, test_version:"1.8", test_version2:"1.8.14"))
  {
    VULN = TRUE;
    fix = "1.8.15";
  }

  else if(version_in_range(version:version, test_version:"1.9", test_version2:"1.9.1"))
  {
    VULN = TRUE;
    fix = "1.9.2";
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:version, fixed_version:fix);
    security_message(data:report, port:cisPort);
    exit(0);
  }
}
