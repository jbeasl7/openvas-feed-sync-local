# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900565");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1882");
  script_name("ImageMagick Buffer Overflow Vulnerability - Linux");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35216/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35111");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_imagemagick_detect_lin.nasl");
  script_mandatory_keys("ImageMagick/Lin/Ver");
  script_tag(name:"impact", value:"Attackers can exploit this issue by executing arbitrary code via a crafted
  TIFF files in the context of an affected application.");
  script_tag(name:"affected", value:"ImageMagick version prior to 6.5.2-9 on Linux.");
  script_tag(name:"insight", value:"The flaw occurs due to an integer overflow error within the 'XMakeImage()'
  function in magick/xwindow.c file while processing malformed TIFF files.");
  script_tag(name:"solution", value:"Upgrade to ImageMagick version 6.5.2-9 or later.");
  script_tag(name:"summary", value:"ImageMagick is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

imageVer = get_kb_item("ImageMagick/Lin/Ver");
if(!imageVer)
  exit(0);

if(version_is_less(version:imageVer, test_version:"6.5.2.9")){
  report = report_fixed_ver(installed_version:imageVer, fixed_version:"6.5.2.9");
  security_message(port: 0, data: report);
}
