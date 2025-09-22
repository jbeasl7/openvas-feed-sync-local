# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801536");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2010-11-04 14:21:53 +0100 (Thu, 04 Nov 2010)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3711");
  script_name("Pidgin Libpurple 'purple_base64_decode()' DoS Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://pidgin.im/news/security/?id=48");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/62708");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2753");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Oct/1024623.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue to crash an affected application.");
  script_tag(name:"affected", value:"Pidgin version prior to 2.7.4 on Windows.");
  script_tag(name:"insight", value:"The issues are caused by errors in 'libpurple' that does not validate the return
  value from 'purple_base64_decode()' function when processing malformed Yahoo!,
  MSN, MySpaceIM, XMPP or NTLM data.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.7.4 or later.");
  script_tag(name:"summary", value:"Pidgin is prone to denial of service (DoS) vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer != NULL)
{
  if(version_is_less(version:pidginVer, test_version:"2.7.4")){
    report = report_fixed_ver(installed_version:pidginVer, fixed_version:"2.7.4");
    security_message(port: 0, data: report);
  }
}
