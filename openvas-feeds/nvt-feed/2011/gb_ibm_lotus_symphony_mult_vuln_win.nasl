# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802227");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_cve_id("CVE-2011-2884", "CVE-2011-2885", "CVE-2011-2886",
                "CVE-2011-2888", "CVE-2011-2893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48936");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IBM Lotus Symphony Multiple Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ibm_lotus_symphony_detect_win.nasl");
  script_mandatory_keys("IBM/Lotus/Symphony/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service.");

  script_tag(name:"affected", value:"IBM Lotus Symphony Version 3 before FP3.");

  script_tag(name:"insight", value:"Multiple flaws are due to unspecified errors related to,

  - critical security vulnerability issues.

  - sample .doc document that incorporates a user-defined toolbar.

  - a .docx document with empty bullet styles for parent bullets.

  - complex graphics in a presentation.

  - a large .xls spreadsheet with an invalid Value reference.");

  script_tag(name:"summary", value:"IBM Lotus Symphony is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to IBM Lotus Symphony version 3 FP3 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

version = get_kb_item("IBM/Lotus/Symphony/Win/Ver");
if(version =~ "^3\.")
{
  if(version_is_less_equal(version:version, test_version:"3.0.10289")){
    report = report_fixed_ver(installed_version:version, vulnerable_range:"Less than or equal to 3.0.10289");
    security_message(port: 0, data: report);
  }
}
