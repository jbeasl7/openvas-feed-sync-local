# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902762");
  script_version("2025-03-05T05:38:53+0000");
  script_cve_id("CVE-2011-4253", "CVE-2011-4252", "CVE-2011-4251", "CVE-2011-4250",
                "CVE-2011-4249", "CVE-2011-4248", "CVE-2011-4247", "CVE-2011-4246",
                "CVE-2011-4245", "CVE-2011-4244", "CVE-2011-4254", "CVE-2011-4255",
                "CVE-2011-4262", "CVE-2011-4261", "CVE-2011-4260", "CVE-2011-4259",
                "CVE-2011-4258", "CVE-2011-4257", "CVE-2011-4256");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-11-29 13:58:17 +0530 (Tue, 29 Nov 2011)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Nov 2011) - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46954/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50741");
  script_xref(name:"URL", value:"http://service.real.com/realplayer/security/11182011_player/en/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes within
  the context of the application and can cause heap overflow or cause denial
  of service.");
  script_tag(name:"affected", value:"RealPlayer versions prior to 15.0.0");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Unspecified errors in RV20, RV10, RV30, ATRC and AAC codec, allows
    attackers to execute arbitrary code via unspecified vectors.

  - An unspecified error related to RealVideo rendering, related to MP4 video
    dimensions can be exploited to corrupt memory.

  - An unspecified error exists when parsing of QCELP streams, MP4 headers,
    MP4 files and the channel within the Cook codec and MLTI chunk length
    within IVR files.

  - An unspecified error exists related to sample size when parsing RealAudio
    files.

  - An unspecified error exists when handling RTSP SETUP requests.");
  script_tag(name:"solution", value:"Upgrade to RealPlayer version 15.0.0 or later");
  script_tag(name:"summary", value:"RealPlayer is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

rpVer = get_kb_item("RealPlayer/Win/Ver");
if(isnull(rpVer)){
  exit(0);
}

# Real player versions < 15.0.0
if(version_is_less(version:rpVer, test_version:"15.0.0.198")){
  report = report_fixed_ver(installed_version:rpVer, fixed_version:"15.0.0.198");
  security_message(port: 0, data: report);
}
