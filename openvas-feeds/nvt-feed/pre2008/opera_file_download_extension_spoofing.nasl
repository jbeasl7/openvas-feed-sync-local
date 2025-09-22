# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


# Ref: Secunia <http://www.secunia.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14247");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2083");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9640");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Opera web browser file download extension spoofing");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"summary", value:"The remote host is using Opera - an alternative web browser.
  This version contains a flaw that may allow a malicious user
  to trick a user into running arbitrary code.
  The issue is triggered when a malicious web site provides a file for download,
  but crafts the filename in such a way that the file is executed, rather than saved.
  It is possible that the flaw may allow arbitrary code execution resulting in a
  loss of confidentiality, integrity, and/or availability.");

  script_tag(name:"solution", value:"Install Opera 7.50 or newer.");
  script_tag(name:"solution_type", value:"VendorFix");
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
