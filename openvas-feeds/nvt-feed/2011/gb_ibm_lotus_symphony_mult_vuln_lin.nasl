# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802229");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_cve_id("CVE-2011-2884", "CVE-2011-2885", "CVE-2011-2886",
                "CVE-2011-2887", "CVE-2011-2888", "CVE-2011-2893");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("IBM Lotus Symphony Multiple Vulnerabilities - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ibm_lotus_symphony_detect_lin.nasl");
  script_mandatory_keys("IBM/Lotus/Symphony/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a denial of service.");
  script_tag(name:"affected", value:"IBM Lotus Symphony Version 3 before FP3.");
  script_tag(name:"insight", value:"Multiple flaws are due to unspecified errors related to,

  - critical security vulnerability issues.

  - sample .doc document that incorporates a user-defined toolbar.

  - a .docx document with empty bullet styles for parent bullets.

  - a certain sample document.

  - complex graphics in a presentation.

  - a large .xls spreadsheet with an invalid Value reference.");
  script_tag(name:"solution", value:"Upgrade to IBM Lotus Symphony version 3 FP3 or later.");
  script_tag(name:"summary", value:"IBM Lotus Symphony is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45271");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48936");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21505448");
  script_xref(name:"URL", value:"http://www-03.ibm.com/software/lotus/symphony/idcontents/releasenotes/en/readme_fixpack3_standalone_long.htm");
  script_xref(name:"URL", value:"https://www-304.ibm.com/jct03001c/software/lotus/symphony/idcontents/releasenotes/en/readme_embedded_in_fixpack3_long.htm");
  script_xref(name:"URL", value:"http://www-03.ibm.com/software/lotus/symphony/buzz.nsf/web_DisPlayPlugin?open&unid=9717F6F587AAA939852578D300404BCF&category=announcements");
  exit(0);
}

include("version_func.inc");

version = get_kb_item("IBM/Lotus/Symphony/Lin/Ver");
if(version =~ "^3\..*")
{
  if(version_is_less(version:version, test_version:"3.0.0.FP3")){
    report = report_fixed_ver(installed_version:version, fixed_version:"3.0.0.FP3");
    security_message(port: 0, data: report);
  }
}
