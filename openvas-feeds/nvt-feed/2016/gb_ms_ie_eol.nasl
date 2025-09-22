# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806657");
  script_version("2025-04-15T05:54:49+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-15 05:54:49 +0000 (Tue, 15 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-01-12 15:30:21 +0530 (Tue, 12 Jan 2016)");
  script_name("Microsoft Internet Explorer (IE) End of Life (EOL) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/lifecycle#gp/Microsoft-Internet-Explorer");

  script_tag(name:"summary", value:"The Microsoft Internet Explorer (IE) version on the remote host
  has reached the End of Life (EOL) and should not be used anymore.");

  script_tag(name:"impact", value:"An EOL version of Microsoft IE is not receiving any security
  updates from the vendor. Unfixed security vulnerabilities might be leveraged by an attacker to
  compromise the security of this host.");

  script_tag(name:"solution", value:"Update the Microsoft IE version on the remote host to a still
  supported version.");

  script_tag(name:"vuldetect", value:"Checks if an EOL version is present on the target host.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("eol_shared.inc");

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1) <= 0) {
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

ver = infos["version"];
if(!ver || ver !~ "^([6-9|1[01])\.")
  exit(0);

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1) > 0) {
  ## Internet Explorer 11 only supported Windows 7 and Server 2008r2
  ## https://support.microsoft.com/en-us/lifecycle#gp/Microsoft-Internet-Explorer
  if(ver !~ "^11\.") {
    VULN = TRUE;
    eol_vers = "< 11.x";
  }
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0) {
  ## Internet Explorer 9 only supported for Windows Vista and Server 2008
  if(ver !~ "^9\.") {
    VULN = TRUE;
    eol_vers = "< 9.x";
  }
}

else if(hotfix_check_sp(win2012:1) > 0) {
  ##Internet Explorer 10 only supported for Windows Server 2012
  if(ver !~ "^10\.") {
    VULN = TRUE;
    eol_vers = "< 10.x";
  }
}

if(VULN) {
  report = eol_build_message(name:"Microsoft Internet Explorer (IE)",
                             cpe:CPE,
                             version:ver,
                             location:infos["location"],
                             eol_version:eol_vers,
                             eol_date:"N/A",
                             eol_type:"prod");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
