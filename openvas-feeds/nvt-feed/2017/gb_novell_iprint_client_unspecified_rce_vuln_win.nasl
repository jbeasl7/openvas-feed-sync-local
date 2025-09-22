# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810591");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2012-0411");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-03-14 13:19:08 +0530 (Tue, 14 Mar 2017)");
  script_name("Novell iPrint Client Unspecified Remote Code Execution Vulnerability - Windows");

  script_tag(name:"summary", value:"Novell iPrint Client is prone to an unspecified remote code
  execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified
  error in Novell iPrint Client.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code via an op-client-interface-version action.");

  script_tag(name:"affected", value:"Novell iPrint Client versions before 5.82 on Windows");

  script_tag(name:"solution", value:"Upgrade to Novell iPrint Client 5.82 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://vulners.com/cve/CVE-2012-0411");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57037");
  script_xref(name:"URL", value:"https://www.novell.com/support/kb/doc.php?id=7008708");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!niVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:niVer, test_version:"5.82"))
{
  report = report_fixed_ver(installed_version:niVer, fixed_version:"5.82");
  security_message(data:report);
  exit(0);
}
