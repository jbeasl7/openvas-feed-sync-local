# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:flashfxp:flashfxp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802965");
  script_version("2025-09-05T15:40:40+0000");
  script_cve_id("CVE-2012-4992");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2012-09-24 14:23:56 +0530 (Mon, 24 Sep 2012)");
  script_name("FlashFXP Multiple Buffer Overflow Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_flashfxp_detect.nasl");
  script_mandatory_keys("FlashFXP/Ver");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73626");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52259");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18555/");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Mar/7");
  script_xref(name:"URL", value:"http://www.flashfxp.com/forum/flashfxp/news/15473-flashfxp-4-2-released.html#post81101");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to overflow a buffer and execute
  arbitrary code on the system or cause the application to crash.");
  script_tag(name:"affected", value:"FlashFXP version 4.1.8.1701");
  script_tag(name:"insight", value:"The flaw is due to improper bounds checking by the TListbox or
  TComboBox.");
  script_tag(name:"solution", value:"Upgrade to FlashFXP version 4.2 or later.");
  script_tag(name:"summary", value:"FlashFXP is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.flashfxp.com/download");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ver = get_app_version(cpe:CPE)) exit(0);

if(version_is_equal(version:ver, test_version:"4.1.8.1701")){
  report = report_fixed_ver(installed_version:ver, fixed_version:"4.2");
  security_message(data:report);
  exit(0);
}

exit(99);
