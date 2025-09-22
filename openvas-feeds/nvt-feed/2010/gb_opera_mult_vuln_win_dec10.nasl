# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801495");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-4579", "CVE-2010-4580", "CVE-2010-4581", "CVE-2010-4582",
                "CVE-2010-4583", "CVE-2010-4584", "CVE-2010-4585", "CVE-2010-4586",
                "CVE-2010-4587");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Opera Browser Multiple Vulnerabilities (Dec 2010) - Windows");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/979/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/977/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/1100/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain sensitive
  information and cause a denial of service.");
  script_tag(name:"affected", value:"Opera Web Browser Version prior 11.00");
  script_tag(name:"insight", value:"Multiple flaws are caused due to:

  - WAP fails to clear 'WML' form fields after manual navigation to a new web
    site, which allows remote attackers to obtain sensitive information.

  - Not properly constrain dialogs to appear on top of rendered documents.

  - Unspecified vulnerability which has unknown impact and attack vectors.

  - Not display a page's security indication, when Opera Turbo is enabled.

  - Not properly handling security policies during updates to extensions.

  - Fails to present information about problematic 'X.509' certificates on
    https web sites, when 'Opera Turbo' is used.

  - Unspecified vulnerability in the auto-update functionality, which leads
    to a denial of service.

  - Fails to implement the Insecure Third Party Module warning message.

  - Enabling 'WebSockets' functionality, which has unspecified impact and
    remote attack vectors.");
  script_tag(name:"solution", value:"Upgrade to Opera Web Browser Version 11.00 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Opera browser is prone to multiple vulnerabilities.");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Win/Version");

if(operaVer)
{
  if(version_is_less(version:operaVer, test_version:"11.00")){
    report = report_fixed_ver(installed_version:operaVer, fixed_version:"11.00");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
