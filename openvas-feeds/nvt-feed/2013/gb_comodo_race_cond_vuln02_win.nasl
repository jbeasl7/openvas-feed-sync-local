# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_tag(name:"impact", value:"Successful exploitation allows local attacker to bypass the defense+
  feature.");
  script_tag(name:"affected", value:"Comodo Internet Security versions before 5.8.213334.2131");
  script_tag(name:"insight", value:"Unspecified flaw that is triggered by multiple race conditions.");
  script_tag(name:"solution", value:"Upgrade to Comodo Internet Security version 5.8.213334.2131 or later.");
  script_tag(name:"summary", value:"Comodo Internet Security is prone to race condition vulnerability.");
  script_oid("1.3.6.1.4.1.25623.1.0.803685");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2011-5118");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-07-05 15:30:09 +0530 (Fri, 05 Jul 2013)");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Comodo Internet Security Race Condition Vulnerability-02");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/429022.php");
  script_xref(name:"URL", value:"http://personalfirewall.comodo.com/release_notes.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_comodo_internet_security_detect_win.nasl");
  script_mandatory_keys("Comodo/InternetSecurity/Win/Ver");
  exit(0);
}


include("version_func.inc");

Ver = get_kb_item("Comodo/InternetSecurity/Win/Ver");

if(Ver)
{
  if(version_is_less(version:Ver, test_version:"5.8.213334.2131")){
    report = report_fixed_ver(installed_version:Ver, fixed_version:"5.8.213334.2131");
    security_message(port: 0, data: report);
    exit(0);
  }
}
