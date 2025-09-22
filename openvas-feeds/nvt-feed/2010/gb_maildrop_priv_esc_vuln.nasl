# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800292");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0301");
  script_name("Maildrop < 2.4.0 Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_maildrop_detect.nasl");
  script_mandatory_keys("Maildrop/Linux/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38367");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55980");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Jan/1023515.html");

  script_tag(name:"summary", value:"Maildrop is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the error in the 'maildrop/main.C', when run
  by root with the '-d' option, uses the gid of root for execution of the mailfilter file in a
  user's home directory.");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to gain elevated
  privileges.");

  script_tag(name:"affected", value:"Maildrop version 2.3.0 and prior.");

  script_tag(name:"solution", value:"Update to version 2.4.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Maildrop/Linux/Ver"))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"2.3.0")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 2.3.0");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
