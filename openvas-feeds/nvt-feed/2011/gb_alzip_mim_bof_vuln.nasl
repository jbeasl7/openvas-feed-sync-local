# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802120");
  script_version("2024-09-13T05:05:46+0000");
  script_cve_id("CVE-2011-1336");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("ALZip <= 8.21 MIM File Processing Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"ALZip is prone to a buffer overflow vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to an error in libETC.dll when processing the
  'filename' field within MIM files.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code in the context of the application. Failed attacks will cause denial-of-service conditions.");

  script_tag(name:"affected", value:"ALZip version 8.21 and prior.");

  script_tag(name:"solution", value:"Update to version 8.21 published after June 29th, 2011 or
  later.");

  script_tag(name:"qod", value:"30"); # nb: See solution above
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000048.html");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210127093320/http://www.securityfocus.com/bid/48493");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

key = "SOFTWARE\ESTsoft\ALZip";
if(!registry_key_exists(key:key))
  exit(0);

if(!version = registry_get_sz(key:key, item:"Version"))
  exit(0);

if(version_is_less_equal(version:version, test_version:"8.21")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"Version 8.21 published after June 29th, 2011.", reg_checked:key + "!Version");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
