# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900597");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2566");
  script_name("TFM MMPlayer '.m3u' Buffer Overflow Vulnerability (Jul 2009)");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_tfm_mmplayer_detect.nasl");
  script_mandatory_keys("TFM/MMPlayer/Ver");

  script_tag(name:"impact", value:"Successful exploitation allows the attacker to execute arbitrary
  code on the system or cause the application to crash.");

  script_tag(name:"affected", value:"TFM MMPlayer version 2.0 through 2.2.0.30.");

  script_tag(name:"insight", value:"This flaw is due to improper bounds checking when processing
  '.m3u' files and can be exploited via crafted '.m3u' playlist file containing
  an overly long string.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"TFM MMPlayer is prone to a stack-based buffer overflow
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35605");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9047");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51442");
  exit(0);
}

include("version_func.inc");

mmplayerVer = get_kb_item("TFM/MMPlayer/Ver");
if(mmplayerVer != NULL)
{
  if(version_in_range(version:mmplayerVer, test_version:"2.0", test_version2:"2.2.0.30")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
