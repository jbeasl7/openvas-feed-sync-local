# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805595");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-2859");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-06-25 14:42:10 +0530 (Thu, 25 Jun 2015)");
  script_name("McAfee ePolicy Orchestrator Man-in-the-Middle Attack Vulnerability (Jun 2015)");

  script_tag(name:"summary", value:"McAfee ePolicy Orchestrator is prone to a man-in-the-middle (MITM) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the application fails to
  properly validate SSL/TLS certificates");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to intercept and manipulate HTTPS traffic between the ePO application
  and registered servers.");

  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator version 4.x
  through 4.6.9 and 5.x through 5.1.2");

  script_tag(name:"solution", value:"Upgrade to McAfee ePolicy Orchestrator
  version 4.6.9 or 5.1.2 or later, and then apply the manual settings listed the
  referenced KB article of the vendor.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/264092");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB84628");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10120");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_in_range(version:version, test_version:"5.0.0", test_version2:"5.1.1")) {
  fix = "Upgrade to 5.1.2 and apply the manual settings";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"4.0.0", test_version2:"4.6.8")) {
  fix = "Upgrade to 4.6.9 and apply the manual settings";
  VULN = TRUE;
}

if(version_is_equal(version:version, test_version:"4.6.9")) {
  fix = "Apply the manual settings";
  VULN = TRUE;
}

if(version_is_equal(version:version, test_version:"5.1.2")) {
  fix = "Apply the manual settings";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
