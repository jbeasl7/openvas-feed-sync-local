# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800994");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4668", "CVE-2009-4676");
  script_name("jetAudio jetCast Title Processing Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35195");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8780");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/503826/100/0/threaded");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_cowon_jetaudio_detect.nasl");
  script_mandatory_keys("JetAudio/Ver");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  and cause a stack-based buffer overflow by tricking the user into opening an
  MP3 or FLAC file containing an overly long title.");
  script_tag(name:"affected", value:"COWON Media Center JetAudio 7.5.2 through 7.5.3.15 on Windows");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in the jetCast component when processing
  song titles.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"COWON Media Center JetAudio is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

jaVer = get_kb_item("JetAudio/Ver");
if(jaVer != NULL)
{
  if(version_in_range(version:jaVer, test_version:"7.5.2", test_version2:"7.5.3.15"))
  {
    exePath = registry_get_sz(key:"SOFTWARE\COWON\Jet-Audio", item:"InstallPath_Main");
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
    file = ereg_replace(pattern:"[A-Z]:(.*)",  replace:"\1",  string:exePath +
                                                              "\JetCast.exe");
    exeVer = GetVer(file:file, share:share);
    if(exeVer != NULL)
    {
      if(version_is_less_equal(version:exeVer, test_version:"2.0.4.1109")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}
