# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811259");
  script_version("2023-06-27T05:05:30+0000");
  script_cve_id("CVE-2017-3622");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-28 19:15:41 +0530 (Fri, 28 Jul 2017)");
  script_name("SUN Solaris Privilege Escalation Vulnerability (Extremeparr)");

  script_tag(name:"summary", value:"Solaris is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in
  'Common Desktop Environment (CDE)' sub component of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  attackers to gain elevated privileges on the affected system.");

  script_tag(name:"affected", value:"Oracle Sun Solaris version 7, 8, 9 and
  10.

  Note: Oracle Sun Solaris version 7, 8, 9 are not supported anymore and will
  not be patched.");

  script_tag(name:"solution", value:"Apply latest patch available for Oracle
  Sun Solaris version 10 or upgrade to Oracle Sun Solaris version 11.");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixSUNS");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97774");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Solaris Local Security Checks");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

# nb: Version check is broken as it doesn't handle the affected package.
# Furthermore get_ssh_solosversion is returning a version like "5.10" and not "10" like assumed previously.
exit(66);
