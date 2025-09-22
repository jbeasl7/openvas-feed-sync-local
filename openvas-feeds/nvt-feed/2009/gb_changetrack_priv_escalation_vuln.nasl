# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900868");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3233");
  script_name("Changetrack Local Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://bugs.debian.org/546791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36420");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36756");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=546791");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/09/16/3");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("secpod_changetrack_detect.nasl");
  script_mandatory_keys("Changetrack/Ver");
  script_tag(name:"impact", value:"Attacker may leverage this issue by executing arbitrary commands via CRLF
  sequences and shell metacharacters in a filename in a directory that is
  checked by changetrack.");
  script_tag(name:"affected", value:"Changetrack version 4.3");
  script_tag(name:"insight", value:"This flaw is generated because the application does not properly handle
  certain file names.");
  script_tag(name:"solution", value:"Upgrade to Changetrack version 4.7 or later");
  script_tag(name:"summary", value:"Changetrack is prone to a local privilege
  escalation vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ctrack_ver = get_kb_item("Changetrack/Ver");
if(!ctrack_ver){
  exit(0);
}

if(version_is_equal(version:ctrack_ver, test_version:"4.3")){
  report = report_fixed_ver(installed_version:ctrack_ver, vulnerable_range:"Equal to 4.3");
  security_message(port: 0, data: report);
}
