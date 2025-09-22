# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802346");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2011-3892", "CVE-2011-3893", "CVE-2011-3894", "CVE-2011-3895",
                "CVE-2011-3896", "CVE-2011-3897", "CVE-2011-3898");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-11-15 10:58:03 +0530 (Tue, 15 Nov 2011)");
  script_name("Google Chrome Multiple Vulnerabilities (Nov 2011) - Linux");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026313");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50642");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2011/11/stable-channel-update.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code,
  cause a denial of service, and disclose potentially sensitive information,
  other attacks may also be possible.");
  script_tag(name:"affected", value:"Google Chrome version prior to 15.0.874.120 on Linux");
  script_tag(name:"insight", value:"Multiple vulnerabilities are due to:

  - A double free error in the Theora decoder exists when handling a crafted
    stream.

  - An error in implementing the MKV and Vorbis media handlers.

  - A memory corruption regression error in VP8 decoding when handling a
    crafted stream.

  - Heap overflow in the Vorbis decoder when handling a crafted stream.

  - Buffer overflow error in the shader variable mapping.

  - A use-after-free error exists related to editing.

  - Fails to ask permission to run applets in Java Runtime Environment (JRE) 7.");
  script_tag(name:"solution", value:"Upgrade to the Google Chrome 15.0.874.120 or later.");
  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"15.0.874.120")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"15.0.874.120");
  security_message(port: 0, data: report);
}
