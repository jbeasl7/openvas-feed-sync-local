# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800730");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2010-0118");
  script_name("Bournal < 1.4.1 Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_bournal_detect.nasl");
  script_mandatory_keys("Bournal/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38554");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38353");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-6/");

  script_tag(name:"summary", value:"Bournal is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists while using temporary files in an insecure
  manner, which may allow attackers to overwrite arbitrary files via symlink attacks when running
  the update check via the '--hack_the_gibson' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform certain
  actions with escalated privileges.");

  script_tag(name:"affected", value:"Bournal prior to version 1.4.1.");

  script_tag(name:"solution", value:"Update to version 1.4.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Bournal/Ver"))
  exit(0);

if(version_is_less(version:vers, test_version:"1.4.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.4.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
