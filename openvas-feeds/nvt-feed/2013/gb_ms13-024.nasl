# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902953");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2013-0080", "CVE-2013-0083", "CVE-2013-0084", "CVE-2013-0085");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2013-03-13 11:50:53 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft SharePoint Server Privilege Elevation Vulnerabilities (2780176)");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2687418");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58367");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58370");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58371");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58372");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2553407");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028278");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-024");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_microsoft_sharepoint_smb_login_detect.nasl");
  script_mandatory_keys("microsoft/sharepoint/server_or_foundation_or_services/smb-login/detected");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to bypass certain security
  restrictions, disclose certain system data and conduct cross-site scripting and spoofing attacks.");

  script_tag(name:"affected", value:"- Microsoft SharePoint Server 2010 Service Pack 1

  - Microsoft SharePoint Foundation 2010 Service Pack 1");

  script_tag(name:"insight", value:"- The application allows users to perform certain actions via HTTP requests
  without performing proper validity checks to verify the requests.

  - Certain unspecified input is not properly sanitized before being returned
  to the user.

  - An error related to the W3WP process when handling URLs can be exploited
  to cause a buffer overflow and subsequently terminate the W3WP process via a specially crafted URL.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS13-024.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

cpe_list = make_list("cpe:/a:microsoft:sharepoint_server", "cpe:/a:microsoft:sharepoint_foundation");

if(!infos = get_app_port_from_list(cpe_list:cpe_list, service:"smb-login"))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if(!infos = get_app_version_and_location(cpe:cpe, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

## SharePoint Server 2007 and 2010
if("cpe:/a:microsoft:sharepoint_server" >< cpe) {
  ## SharePoint Server 2010 (wosrv)
  if(vers =~ "^14\.") {
    ## Not getting updated any file so checking for hotfix
    if(hotfix_missing(name:"2553407") == 1) {
      security_message(port:port, data:"The target host was found to be vulnerable");
      exit(0);
    }
  }
}

## SharePoint Foundation 2010
else if("cpe:/a:microsoft:sharepoint_foundation" >< cpe) {
  key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0";
  if(registry_key_exists(key:key)) {
    dllPath = registry_get_sz(key:key, item:"Location");
    if(dllPath) {
      dllVer = fetch_file_version(sysPath:dllPath, file_name:"BIN\Onetutil.dll");
      if(dllVer) {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6134.5000")) {
          report = report_fixed_ver(installed_version:dllVer, vulnerable_range:"14.0 - 14.0.6134.5000", install_path:dllPath);
          security_message(port:port, data:report);
          exit(0);
        }
      }
    }
  }
}

exit(99);
