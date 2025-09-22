# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900683");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0690", "CVE-2009-0691");
  script_name("Foxit Reader Multiple Denial of Service Vulnerabilities (Jun 2009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_foxit_reader_detect_portable_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("foxit/reader/ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35512");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35442");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35443");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1640");
  script_xref(name:"URL", value:"http://www.foxitsoftware.com/pdf/reader/security.htm#0602");

  script_tag(name:"impact", value:"Successful exploitation will let attacker execute arbitrary code or crash an
  affected application.");

  script_tag(name:"affected", value:"Foxit Reader 3.0 before Build 1817 and JPEG2000/JBIG2 Decoder
  before 2.0.2009.616.");

  script_tag(name:"insight", value:"Multiple errors exist in the Foxit JPEG2000/JBIG2 Decoder add-on.

  - An error occurs while processing a negative value for the stream offset
    in a JPX stream.

  - A fatal error while decoding JPX header which results in a subsequent
    invalid address access.");

  script_tag(name:"summary", value:"Foxit Reader is prone to multiple Denial of Service vulnerabilities.");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!foxVer = get_kb_item("foxit/reader/ver")) exit(0);

if(version_in_range(version:foxVer,test_version:"3.0" ,test_version2:"3.0.2009.1817"))
{
  foxitPath = registry_get_sz(key:"SOFTWARE\Foxit Software\Foxit Reader",
                                 item:"InstallPath");
  if(foxitPath)
  {
    foxitPath = foxitPath + "fxdecod1.dll";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:foxitPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:foxitPath);
    fxdecodVer = GetVer(share:share, file:file);
    if((fxdecodVer) &&
      (version_is_less(version:fxdecodVer,test_version:"2.0.2009.616"))){
      report = report_fixed_ver(installed_version:fxdecodVer, fixed_version:"2.0.2009.616");
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
