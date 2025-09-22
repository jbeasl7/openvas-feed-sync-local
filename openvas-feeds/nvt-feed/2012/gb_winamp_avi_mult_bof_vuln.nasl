# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802926");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-4045");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-02 18:57:35 +0530 (Thu, 02 Aug 2012)");
  script_name("Winamp 'AVI' File Multiple Heap-based Buffer Overflow Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46624");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54131");
  script_xref(name:"URL", value:"http://forums.winamp.com/showthread.php?t=345684");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_mandatory_keys("Winamp/Version");
  script_tag(name:"insight", value:"Errors in bmp.w5s,

  - when allocating memory using values from the 'strf' chunk to process BI_RGB
    video and UYVY video data within AVI files.

  - when processing decompressed TechSmith Screen Capture Codec (TSCC) data
    within AVI files.");
  script_tag(name:"solution", value:"Upgrade to Winamp 5.63 build 3235 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Winamp is prone to heap-based buffer overflow vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in the
  context of the application.");
  script_tag(name:"affected", value:"Winamp version before 5.63 build 3235");
  exit(0);
}

include("version_func.inc");

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

if(version_is_less(version:winampVer, test_version:"5.6.3.3235")){
  report = report_fixed_ver(installed_version:winampVer, fixed_version:"5.6.3.3235");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
