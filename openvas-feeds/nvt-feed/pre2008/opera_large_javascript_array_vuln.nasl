# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Ref: d3thStaR <d3thStaR@rootthief.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14248");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1810");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9869");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Opera web browser large javaScript array handling vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"solution", value:"Install Opera 7.50 or newer.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is using Opera - an alternative web browser.
  This version is vulnerable to an issue when handling
  large JavaScript arrays.

  In particular, it is possible to crash the browser when performing
  various operations on Array objects with 99999999999999999999999
  or 0x23000000 elements.

  The crash is due to a segmentation fault and may be indicative
  of an exploitable memory corruption vulnerability,
  possibly resulting in arbitrary code execution.");
  exit(0);
}

include("version_func.inc");

OperaVer = get_kb_item("Opera/Win/Version");
if(!OperaVer){
  exit(0);
}

if(version_is_less_equal(version:OperaVer, test_version:"7.49")){
  report = report_fixed_ver(installed_version:OperaVer, vulnerable_range:"Less than or equal to 7.49");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

