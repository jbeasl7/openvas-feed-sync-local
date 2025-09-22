# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801542");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-11-16 10:37:01 +0100 (Tue, 16 Nov 2010)");
  script_cve_id("CVE-2010-1523");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Winamp VP6 Content Parsing Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-95/");
  script_xref(name:"URL", value:"http://forums.winamp.com/showthread.php?t=322995");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/514484/100/0/threaded");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Winamp/Version");
  script_tag(name:"insight", value:"The flaw is caused by an error in the VP6 codec (vp6.w5s) when parsing VP6
  video content. This can be exploited to cause a heap-based buffer overflow
  via a specially crafted media file or stream.");
  script_tag(name:"solution", value:"upgrade to Winamp 5.59 Beta build 3033 or later.");
  script_tag(name:"summary", value:"Winamp is prone to heap-based buffer overflow vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code or
  can  be exploited by malicious people to potentially compromise a user's
  system.");
  script_tag(name:"affected", value:"Winamp version before 5.59 Beta build 3033 (5.5.9.3033)");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

if(version_is_less(version:winampVer, test_version:"5.5.9.3033"))
{
  winPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths\winamp.exe", item:"Path");
  if(!winPath){
    exit(0);
  }

  winPath =  winPath + "\System\vp6.w5s";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:winPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:winPath);
  dllSize = get_file_size(share:share, file:file);
  if(dllSize){
    report = report_fixed_ver(installed_version:winampVer, fixed_version:"5.5.9.3033", install_path:winPath);
    security_message(port: 0, data: report);
  }
}
