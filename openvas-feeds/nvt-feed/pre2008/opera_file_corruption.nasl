# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Ref: :: Operash ::

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14246");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9279");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Opera relative path directory traversal file corruption vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_dependencies("gb_opera_detect_portable_win.nasl");
  script_mandatory_keys("Opera/Win/Version");
  script_tag(name:"solution", value:"Install Opera 7.23 or newer.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is using Opera - an alternative web browser.
  This version of Opera is vulnerable to a file corruption vulnerability.
  This issue is exposed when a user is presented with a file dialog,
  which will cause the creation of a temporary file.
  It is possible to specify a relative path to another file on the system
  using directory traversal sequences when the download dialog is displayed.
  If the client user has write permissions to the attacker-specified file,
  it will be corrupted.

  This could be exploited to delete sensitive files on the systems.");
  exit(0);
}


include("version_func.inc");

OperaVer = get_kb_item("Opera/Win/Version");
if(!OperaVer){
  exit(0);
}

if(version_is_less_equal(version:OperaVer, test_version:"7.22")){
  report = report_fixed_ver(installed_version:OperaVer, vulnerable_range:"Less than or equal to 7.22");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
