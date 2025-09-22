# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801339");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-0998", "CVE-2010-0999");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Free Download Manager Multiple Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39447");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-68/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511282/100/0/threaded");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_free_download_mang_detect.nasl");
  script_mandatory_keys("FreeDownloadManager/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary code
  in the context of the application or to compromise the application and the
  underlying computer.");
  script_tag(name:"affected", value:"Free Download Manager version prior to 3.0 build 852 on Windows.");
  script_tag(name:"insight", value:"Multiple buffer overflow errors exist due to boundary errors when,

  - opening folders within the 'Site Explorer'

  - opening websites in the 'Site Explorer' functionality

  - setting the directory on 'FTP' servers

  - handling redirects and

  - Sanitising the 'name' attribute of the 'file' element of
    metalink files before using it to download files.");
  script_tag(name:"solution", value:"Upgrade to version 3.0 build 852.");
  script_tag(name:"summary", value:"Free Download Manager is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

fdmVer = get_kb_item("FreeDownloadManager/Ver");
if(!fdmVer){
  exit(0);
}

if(version_is_less(version:fdmVer, test_version:"3.0.852.0")){
  report = report_fixed_ver(installed_version:fdmVer, fixed_version:"3.0.852.0");
  security_message(port: 0, data: report);
}
