# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Ref: GreyMagic Software

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14261");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2570");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Opera remote location object cross-domain scripting vulnerability");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"solution", value:"Upgrade to Opera 7.54 or newer.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host contains a web browser that is affected by
  multiple flaws.

  Description :
  The remote host is using Opera, an alternative web browser.
  This version of Opera on the remote host fails to block write access to
  the 'location' object.  This could allow a user to create a specially
  crafted URL to overwrite methods within the 'location' object that would
  execute arbitrary code in a user's browser within the trust relationship
  between the browser and the server, leading to a loss of confidentiality
  and integrity.");
  script_xref(name:"URL", value:"http://www.greymagic.com/security/advisories/gm008-op/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10873");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/windows/754/");
  exit(0);
}


include("version_func.inc");

OperaVer = get_kb_item("Opera/Win/Version");
if(!OperaVer){
  exit(0);
}

if(version_is_less_equal(version:OperaVer, test_version:"7.53")){
  report = report_fixed_ver(installed_version:OperaVer, vulnerable_range:"Less than or equal to 7.53");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
