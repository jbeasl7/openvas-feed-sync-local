# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801562");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-12-13 15:28:53 +0100 (Mon, 13 Dec 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4508");
  script_name("Mozilla Firefox Browser 4.x < 4.0 Beta 8 Security Bypass Vulnerabilities - Windows");
  script_xref(name:"URL", value:"https://wiki.mozilla.org/Platform/2010-12-07");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass intended
  access restrictions.");

  script_tag(name:"affected", value:"Firefox version 4.0 through 4.0 Beta 7.");

  script_tag(name:"insight", value:"The flaw is due to error in 'WebSockets' implementation, does
  not properly perform proxy upgrade negotiation, which has unspecified impact and remote attack
  vectors.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox 4 Beta 8 or later.");

  script_tag(name:"summary", value:"Mozilla Firefox browser is prone to a security bypass
  vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Firefox/Win/Ver"))
  exit(0);

if(version_in_range(version:vers, test_version:"4.0", test_version2:"4.0.b7")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"4.0 - 4.0.b7");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
