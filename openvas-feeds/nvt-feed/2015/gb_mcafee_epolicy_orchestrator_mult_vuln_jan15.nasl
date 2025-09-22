# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805238");
  script_version("2024-03-08T15:37:10+0000");
  script_cve_id("CVE-2015-0922", "CVE-2015-0921");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-08 15:37:10 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-01-12 20:02:18 +0530 (Mon, 12 Jan 2015)");
  script_name("McAfee ePolicy Orchestrator Multiple Vulnerabilities (Jan 2015)");

  script_tag(name:"summary", value:"McAfee ePolicy Orchestrator is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - an incorrectly configured XML parser accepting XML external entities from an
  untrusted source.

  - application uses the same secret key across different customers installation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to obtain the administrator password and gain access to arbitrary files.");

  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator version before
  4.6.9 and 5.x before 5.1.2");

  script_tag(name:"solution", value:"Upgrade to McAfee ePolicy Orchestrator
  version 4.6.9 or 5.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/129827");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/8");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10095");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
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

if(version_is_less(version:version, test_version:"4.6.9")||
   version_in_range(version:version, test_version:"5.0.0", test_version2:"5.1.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.6.9/5.1.2");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
