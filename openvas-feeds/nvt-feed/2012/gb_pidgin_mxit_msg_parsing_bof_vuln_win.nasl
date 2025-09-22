# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803102");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2012-3374");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-10-19 13:10:50 +0530 (Fri, 19 Oct 2012)");
  script_name("Pidgin MXit Message Parsing Buffer Overflow Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49831/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54322");
  script_xref(name:"URL", value:"http://hg.pidgin.im/pidgin/main/rev/ded93865ef42");
  script_xref(name:"URL", value:"http://www.pidgin.im/news/security/index.php?id=64");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause a
  stack-based buffer overflow via a specially crafted RX message which may lead to the execution of
  arbitrary code in the context of the application or to denial-of-service.");

  script_tag(name:"affected", value:"Pidgin version prior to 2.10.5.");

  script_tag(name:"insight", value:"A boundary error within the 'mxit_show_message()' function, when
 parsing incoming instant messages containing inline images.");

  script_tag(name:"solution", value:"Update to version 2.10.5 or later.");

  script_tag(name:"summary", value:"Pidgin is prone to a buffer overflow vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer)
{
  if(version_is_less(version:pidginVer, test_version:"2.10.5")){
    report = report_fixed_ver(installed_version:pidginVer, fixed_version:"2.10.5");
    security_message(port:0, data:report);
  }
}
