# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107084");
  script_version("2026-04-29T06:25:32+0000");
  script_tag(name:"last_modification", value:"2026-04-29 06:25:32 +0000 (Wed, 29 Apr 2026)");
  script_tag(name:"creation_date", value:"2016-11-15 16:34:55 +0700 (Tue, 15 Nov 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_name("FTPShell Client 4.1 RC2 Name Session Stack Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Buffer overflow");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/9426/");

  script_tag(name:"summary", value:"FTPShell Client is prone to a stack overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  code and cause a stack overflow in the application.");

  script_tag(name:"affected", value:"FTPShell Client version 4.1 RC2.");

  script_tag(name:"solution", value:"No solution is required.

  Note: This VT is deprecated and thus doesn't require a solution.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

# nb: This VT did a version check for version "4.1 RC2" only which was never extracted from the
# detection itself. As this is a low priority product the complete VT got deprecated.
exit(66);
