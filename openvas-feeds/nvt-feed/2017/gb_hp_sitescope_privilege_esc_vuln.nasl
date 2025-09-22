# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:hp:sitescope";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807398");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-2120");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:C");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2017-02-14 15:29:33 +0530 (Tue, 14 Feb 2017)");
  script_name("HP SiteScope Remote Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"HP SiteScope is prone to remote privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The specific flaw exists within the
  'Log Analysis Tool', which does not validate or restrict the log path allowing the
  users to read the 'users.config' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to escalate privileges from the user to administrator role.");

  script_tag(name:"affected", value:"HP SiteScope versions 11.1x before 11.13,
  11.2x before 11.24.391, and 11.3x before 11.30.521");

  script_tag(name:"solution", value:"Upgrade to SiteScope 11.13, or 11.24.391,
  or 11.30.521, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-239");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74801");
  script_xref(name:"URL", value:"https://h20566.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c04688784");
  script_xref(name:"URL", value:"http://www8.hp.com/us/en/software-solutions/sitescope-application-monitoring/index.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_hp_sitescope_detect.nasl");
  script_mandatory_keys("hp/sitescope/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"11.10", test_version2:"11.12")) {
  fix = "11.13";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"11.20", test_version2:"11.24.390")) {
  fix = "11.24.391";
  VULN = TRUE;
}

else if(version_in_range(version:version, test_version:"11.30", test_version2:"11.30.520")) {
  fix = "11.30.521";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
