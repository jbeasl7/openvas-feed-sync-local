# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803688");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2010-5185");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-07-05 15:51:39 +0530 (Fri, 05 Jul 2013)");
  script_name("Comodo Internet Security Unspecified Vulnerability");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/429014.php");
  script_xref(name:"URL", value:"http://personalfirewall.comodo.com/release_notes.html");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_comodo_internet_security_detect_win.nasl");
  script_mandatory_keys("Comodo/InternetSecurity/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code or may
  cause denial of service condition.");
  script_tag(name:"affected", value:"Comodo Internet Security versions before 5.3.174622.1216");
  script_tag(name:"insight", value:"Flaw related to the antivirus component, does not validate the revocation
  status of the X.509 certificates in signed binaries.");
  script_tag(name:"solution", value:"Upgrade to Comodo Internet Security version 5.3.174622.1216 or later.");
  script_tag(name:"summary", value:"Comodo Internet Security is prone to an unspecified vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

Ver = get_kb_item("Comodo/InternetSecurity/Win/Ver");

if(Ver)
{
  if(version_is_less(version:Ver, test_version:"5.3.174622.1216")){
    report = report_fixed_ver(installed_version:Ver, fixed_version:"5.3.174622.1216");
    security_message(port:0, data:report);
    exit(0);
  }
}
