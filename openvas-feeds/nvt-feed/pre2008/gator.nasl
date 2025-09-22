# SPDX-FileCopyrightText: 2003 Jeff Adams
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11883");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Gator/GAIN Spyware Installed");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Jeff Adams");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution", value:"Uninstall the software");

  script_tag(name:"summary", value:"The remote host has Gator/GAIN Spyware Installed. Gator tracks the sites that
  users visit and forwards that data back to the company's servers. Gator sells
  the use of this information to advertisers. It also lets companies launch a
  pop-up ad when users visit various Web sites. This software is not suitable
  for a business environment.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

rootfile = registry_get_sz(key:"SOFTWARE\Gator.com\Gator\dyn", item:"AppExe");
if(rootfile)
{
 security_message(get_kb_item("SMB/transport"));
}
