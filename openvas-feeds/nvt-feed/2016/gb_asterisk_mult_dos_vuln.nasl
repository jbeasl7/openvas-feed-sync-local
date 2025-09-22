# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:digium:asterisk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807712");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-03-23 11:31:35 +0530 (Wed, 23 Mar 2016)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");


  script_cve_id("CVE-2016-2232", "CVE-2016-2316");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Asterisk Multiple Denial of Service Vulnerabilities");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_digium_asterisk_sip_detect.nasl");
  script_mandatory_keys("digium/asterisk/detected");

  script_tag(name:"summary", value:"Asterisk is prone to multiple denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - An error in 'chan_sip' function when the 'timert1 sip.conf' configuration
    is set to a value greater than 1245]

  - An input validation error in UDPTL FAX packet.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service condition.");

  script_tag(name:"affected", value:"Asterisk version 1.8.x and 11.x before 11.21.1, 12.x and 13.x
  before 13.7.1.");

  script_tag(name:"solution", value:"Update to version 11.21.1 or 13.7.1 or later.");

  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2016-002.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83352");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82651");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2016-003.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

astPort = get_app_port(cpe:CPE);
if(!astPort){
  exit(0);
}

astVer = get_app_version(cpe:CPE, port:astPort);
if(isnull(astVer)){
  exit(0);
}

if((astVer =~ "^(1\.8)")||
    version_in_range(version:astVer, test_version:"11.0.0", test_version2:"11.21.0"))
{
  fix = "11.21.1";
  VULN = TRUE;
}

else if(version_in_range(version:astVer, test_version:"12.0.0", test_version2:"13.7.0"))
{
  fix = "13.7.1";
  VULN = TRUE;
}

if(VULN)
{
    report = report_fixed_ver(installed_version:astVer, fixed_version:fix);
    security_message(port:astPort, data:report, proto:"udp");
    exit(0);
}
