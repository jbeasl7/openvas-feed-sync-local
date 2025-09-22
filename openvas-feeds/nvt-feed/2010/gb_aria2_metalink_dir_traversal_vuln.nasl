# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801341");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1512");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Aria2 metalink 'name' Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-71/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40142");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511280/100/0/threaded");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_aria2_detect.nasl");
  script_mandatory_keys("Aria2/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to download files to directories
  outside of the intended download directory via directory traversal attacks.");
  script_tag(name:"affected", value:"Aria2 version prior to 1.9.3");
  script_tag(name:"insight", value:"The flaw is due to an error in the handling of metalink files. The 'name'
  attribute of a 'file' element in a metalink file is not properly sanitised.");
  script_tag(name:"solution", value:"Upgrade to Aria2 1.9.3.");
  script_tag(name:"summary", value:"Aria2 is prone to a directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

aria2Ver = get_kb_item("Aria2/Ver");
if(!aria2Ver){
  exit(0);
}

if(version_is_less(version:aria2Ver, test_version:"1.9.3")){
  report = report_fixed_ver(installed_version:aria2Ver, fixed_version:"1.9.3");
  security_message(port: 0, data: report);
}
