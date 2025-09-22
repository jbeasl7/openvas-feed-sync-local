# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:goldengate";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807249");
  script_version("2025-01-21T05:37:33+0000");
  script_cve_id("CVE-2016-0452", "CVE-2016-0451", "CVE-2016-0450");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-02-12 13:49:29 +0530 (Fri, 12 Feb 2016)");
  script_name("Oracle GoldenGate Multiple Unspecified Vulnerabilities (Feb 2016) - Windows");

  script_tag(name:"summary", value:"Oracle GoldenGate is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on confidentiality, integrity and availability
  via unknown vectors.");

  script_tag(name:"affected", value:"Oracle GoldenGate 11.2 and 12.1.2 on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/81122");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/81125");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/81117");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_oracle_goldengate_detect.nasl");
  script_mandatory_keys("Oracle/GoldenGate/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!golVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:golVer, test_version:"11.2")||
   version_is_equal(version:golVer, test_version:"12.1.2"))
{
  report = report_fixed_ver(installed_version:golVer, fixed_version:"Apply the patch");
  security_message(data:report);
  exit(0);
}
