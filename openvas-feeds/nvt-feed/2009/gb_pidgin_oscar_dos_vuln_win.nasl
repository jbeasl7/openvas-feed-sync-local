# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800823");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1889");
  script_name("Pidgin OSCAR Protocol Denial Of Service Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35652");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35530");
  script_xref(name:"URL", value:"http://developer.pidgin.im/ticket/9483");
  script_xref(name:"URL", value:"http://pidgin.im/pipermail/devel/2009-May/008227.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_mandatory_keys("Pidgin/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause an application crash.");
  script_tag(name:"affected", value:"Pidgin version prior to 2.5.8 on Windows");
  script_tag(name:"insight", value:"Error in OSCAR protocol implementation leads to the application misinterpreting
  the ICQWebMessage message type as ICQSMS message type via a crafted ICQ web
  message that triggers allocation of a large amount of memory.");
  script_tag(name:"solution", value:"Upgrade to Pidgin version 2.5.8.");
  script_tag(name:"summary", value:"Pidgin is prone to a denial of service (DoS)
  vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(!pidginVer)
  exit(0);

if(version_is_less(version:pidginVer, test_version:"2.5.8")){
  report = report_fixed_ver(installed_version:pidginVer, fixed_version:"2.5.8");
  security_message(port: 0, data: report);
}
