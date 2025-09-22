# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:endpoint_protection";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812068");
  script_version("2025-09-19T15:40:40+0000");
  script_cve_id("CVE-2017-13681");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-19 15:40:40 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-11-08 11:56:13 +0530 (Wed, 08 Nov 2017)");
  script_name("Symantec Endpoint Protection Privilege Escalation Vulnerability (SYM17-011)");

  script_tag(name:"summary", value:"Symantec Endpoint Protection is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to unspecified error
  within the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attacker to gain elevated privileges on the affected system.");

  script_tag(name:"affected", value:"Symantec Endpoint Protection prior to SEP
  12.1 RU6 MP9");

  script_tag(name:"solution", value:"Upgrade to SEP 12.1 RU6 MP9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20171106_00");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101504");

  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
sepVer = infos["version"];
sepPath = infos["location"];

if(version_is_less_equal(version:sepVer, test_version:"12.1.7266.6800"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"SEP 12.1 RU6 MP9", install_path:sepPath);
  security_message(data:report);
  exit(0);
}
exit(0);
