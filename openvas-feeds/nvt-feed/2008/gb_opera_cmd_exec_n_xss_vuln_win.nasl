# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800048");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4794", "CVE-2008-4795");
  script_name("Opera Web Browser Command Execution and XSS Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/906/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31991");
  script_xref(name:"URL", value:"http://www.opera.com/support/search/view/907/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");

  script_tag(name:"impact", value:"Successful remote attack could inject arbitrary HTML and script code,
  launch cross site scripting attacks on user's browser session when malicious data is being viewed.");

  script_tag(name:"affected", value:"Opera version prior to 9.62 on Windows.");

  script_tag(name:"insight", value:"Flaws are due to:

  - certain parameters passed to the History Search functionality are not
    properly sanitised before being used.

  - an error exists in the handling of Javascript URLs in the Links panel.");

  script_tag(name:"solution", value:"Upgrade to Opera 9.62.");

  script_tag(name:"summary", value:"Opera Web Browser is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"9.62")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"9.62");
  security_message(port: 0, data: report);
}
