# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800275");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1260");
  script_name("UltraISO Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34581");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34363");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8343");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49672");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_ultraiso_detect.nasl");
  script_mandatory_keys("UltraISO/Ver");
  script_tag(name:"affected", value:"UltraISO version 9.3.3.2685 and prior.");
  script_tag(name:"insight", value:"This flaw is due to inadequate boundary check while processing 'CCD'
  or 'IMG' files.");
  script_tag(name:"solution", value:"Upgrade to UltraISO version 9.3.6.2750 or later.");
  script_tag(name:"summary", value:"UltraISO is prone to Stack-Based Buffer Overflow Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can cause stack overflow or denial of service.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ultraVer = get_kb_item("UltraISO/Ver");
if(!ultraVer)
  exit(0);

if(version_is_less_equal(version:ultraVer, test_version:"9.3.3.2685")){
  report = report_fixed_ver(installed_version:ultraVer, vulnerable_range:"Less than or equal to 9.3.3.2685");
  security_message(port: 0, data: report);
}
