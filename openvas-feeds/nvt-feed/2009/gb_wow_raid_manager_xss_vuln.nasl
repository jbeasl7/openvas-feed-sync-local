# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900515");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-6161");
  script_name("WoW Raid Manager Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32172");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31661");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=631789");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_wow_raid_manager_detect.nasl");
  script_mandatory_keys("WoWRaidManager/Ver");
  script_tag(name:"impact", value:"Successful remote exploitation will let the attacker execute
  arbitrary code in the scope of the application. As a result the attacker
  may gain sensitive information and use it to redirect the user to any
  other malicious URL.");
  script_tag(name:"affected", value:"WoW Raid Manager versions prior to 3.5.1.");
  script_tag(name:"insight", value:"The flaw exists due to WoW Raid Manager fails to properly sanitise user
  supplied input.");
  script_tag(name:"solution", value:"Upgrade to version 3.5.1.");
  script_tag(name:"summary", value:"WoW Raid Manager is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

wowVer = get_kb_item("WoWRaidManager/Ver");
if(!wowVer)
  exit(0);

if(version_is_less(version:wowVer, test_version:"3.5.1")){
  report = report_fixed_ver(installed_version:wowVer, fixed_version:"3.5.1");
  security_message(port: 0, data: report);
}
