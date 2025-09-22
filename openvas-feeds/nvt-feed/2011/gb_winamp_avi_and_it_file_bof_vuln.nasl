# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902652");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-4857", "CVE-2011-3834");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-12-22 12:11:40 +0530 (Thu, 22 Dec 2011)");
  script_name("Winamp AVI And IT Files Parsing Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46882");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51015");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Dec/321");
  script_xref(name:"URL", value:"http://forums.winamp.com/showthread.php?t=332010");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  script_tag(name:"insight", value:"Flaws are due to an error in,

  - 'in_avi.dll' plugin when parsing an AVI file with a crafted value for
    the number of streams or the size of the RIFF INFO chunk.

  - 'in_mod.dll' plugin when parsing a crafted song message data in an Impulse
    Tracker (IT) file.");
  script_tag(name:"solution", value:"Upgrade to Winamp 5.623 or later.");
  script_tag(name:"summary", value:"Winamp is prone to buffer overflow vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code or
  cause a buffer overflow.");
  script_tag(name:"affected", value:"Nullsoft Winamp version 5.622 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

if(version_is_less_equal(version:winampVer, test_version:"5.6.2.3189")){
  report = report_fixed_ver(installed_version:winampVer, vulnerable_range:"Less than or equal to 5.6.2.3189");
  security_message(port: 0, data: report);
}
