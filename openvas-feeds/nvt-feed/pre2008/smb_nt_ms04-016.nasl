# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12267");
  script_version("2023-08-01T13:29:10+0000");
  script_cve_id("CVE-2004-0202");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Microsoft DirectPlay DoS Vulnerability (839643)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"A denial of service (DoS) vulnerability exists in the
  implementation of the IDirectPlay4 application programming interface (API) of Microsoft DirectPlay
  because of a lack of robust packet validation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If a user is running a networked DirectPlay application, an
  attacker who successfully exploited this vulnerability could cause the DirectPlay application to
  fail. The user would have to restart the application to resume functionality.");

  script_tag(name:"solution", value:"The vendor has released updates, please see the references for
  more information.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-016");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10487");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if(!dvers = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version"))
  exit(0);

if(!vers = get_kb_item("SMB/WindowsVersion"))
  exit(0);

if(vers == "5.0") {
  if((dvers != "4.08.00.0400") &&
     (dvers != "4.08.00.0400") &&
     (dvers != "4.08.01.0881") &&
     (dvers != "4.08.01.0901") &&
     (dvers != "4.08.02.0134") &&
     (dvers != "4.09.00.0900") &&
     (dvers != "4.09.00.0901") &&
     (dvers != "4.09.00.0902"))
    exit(0);
}

if(vers == "5.1") {
  if((dvers != "4.08.02.0134") &&
     (dvers != "4.09.00.0900") &&
     (dvers != "4.09.00.0901") &&
     (dvers != "4.09.00.0902"))
   exit(0);
}

if(vers == "5.2") {
  if((dvers != "4.09.00.0900") &&
     (dvers != "4.09.00.0901") &&
     (dvers != "4.09.00.0902"))
    exit (0);
}

if(hotfix_check_sp(win2k:5, xp:2, win2003:1) <= 0)
  exit(0);

if(hotfix_missing(name:"KB839643") > 0 &&
   hotfix_missing(name:"KB839643-DirectX8") > 0 &&
   hotfix_missing(name:"KB839643-DirectX81") > 0 &&
   hotfix_missing(name:"KB839643-DirectX82") > 0 &&
   hotfix_missing(name:"KB839643-DirectX9")  > 0) {
  security_message(port:0);
  exit(0);
}

exit(99);
