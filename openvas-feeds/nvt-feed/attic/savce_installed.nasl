# SPDX-FileCopyrightText: 2008 Jeff Adams / Tenable Network Security
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80040");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 20:38:19 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Symantec Anti Virus Corporate Edition Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Jeff Adams / Tenable Network Security");
  script_family("Product detection");

  script_tag(name:"solution", value:"Make sure SAVCE is installed, running and using the latest
  VDEFS.");

  script_tag(name:"summary", value:"This plugin checks that the remote host has Symantec AntiVirus
  Corporate installed and properly running, and makes sure that the latest Vdefs are loaded.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

##This VT is deprecated as it produces false positives.
## Moreover it is not referenced by any of the VTs.
exit(66);
