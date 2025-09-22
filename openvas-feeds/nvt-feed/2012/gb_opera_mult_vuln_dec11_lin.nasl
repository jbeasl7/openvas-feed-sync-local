# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802834");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2011-4681", "CVE-2011-4682", "CVE-2011-4683", "CVE-2011-4684",
                "CVE-2011-4685", "CVE-2011-4686", "CVE-2011-4687");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-04-09 16:54:45 +0530 (Mon, 09 Apr 2012)");
  script_name("Opera Multiple Vulnerabilities (Dec 2011) - Linux");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1003/");
  script_xref(name:"URL", value:"http://www.opera.com/support/kb/view/1005/");
  script_xref(name:"URL", value:"http://www.opera.com/docs/changelogs/unix/1160/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_mandatory_keys("Opera/Linux/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions, or cause a denial of service condition.");
  script_tag(name:"affected", value:"Opera version before 11.60 on Linux");
  script_tag(name:"insight", value:"Multiple flwas are due to:

  - Improper handling of the number of .(dot) characters that conventionally
    exist in domain names of different top-level domains.

  - Implementation errors in the 'JavaScript' engine, 'Web Workers' and 'in'
    operator.

  - An error when handling certificate revocation related to 'corner cases'.

  - An error in Dragonfly in opera.");
  script_tag(name:"solution", value:"Upgrade to the Opera version 11.60 or later.");
  script_tag(name:"summary", value:"Opera is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"11.60")){
  report = report_fixed_ver(installed_version:operaVer, fixed_version:"11.60");
  security_message(port:0, data:report);
}
