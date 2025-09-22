# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800352");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0414");
  script_name("Tor Unspecified Remote Memory Corruption Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33635");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33399");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33677");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Jan/1021633.html");
  script_xref(name:"URL", value:"http://blog.torproject.org/blog/tor-0.2.0.33-stable-released");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_tor_detect_win.nasl");
  script_mandatory_keys("Tor/Win/Ver");
  script_tag(name:"affected", value:"Tor version prior to 0.2.0.33 on Windows.");
  script_tag(name:"insight", value:"Due to unknown impact, remote attackers can trigger heap corruption on
  the application.");
  script_tag(name:"solution", value:"Upgrade to version 0.2.0.33 or later.");
  script_tag(name:"summary", value:"Tor is prone to unspecified remote Memory Corruption vulnerability.");
  script_tag(name:"impact", value:"A remote user could execute arbitrary code on the target system and can
  cause denial-of-service or compromise a vulnerable system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

torVer = get_kb_item("Tor/Win/Ver");
if(!torVer)
  exit(0);

if(version_is_less(version:torVer, test_version:"0.2.0.33")){
  report = report_fixed_ver(installed_version:torVer, fixed_version:"0.2.0.33");
  security_message(port: 0, data: report);
}
