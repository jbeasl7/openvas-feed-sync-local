# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902847");
  script_version("2025-08-05T05:45:17+0000");
  script_cve_id("CVE-2012-1858", "CVE-2012-1859", "CVE-2012-1860", "CVE-2012-1861",
                "CVE-2012-1862", "CVE-2012-1863");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-08-05 05:45:17 +0000 (Tue, 05 Aug 2025)");
  script_tag(name:"creation_date", value:"2012-07-11 11:11:11 +0530 (Wed, 11 Jul 2012)");
  script_name("Microsoft SharePoint Multiple Privilege Elevation Vulnerabilities (2695502)");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1027232");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54312");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54313");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54314");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54315");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54316");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-050");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_microsoft_sharepoint_smb_login_detect.nasl", "secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to bypass certain security
  restrictions and conduct cross-site scripting and spoofing attacks.");

  script_tag(name:"affected", value:"- Microsoft InfoPath 2010

  - Microsoft Groove Server 2010

  - Microsoft Office Web Apps 2010

  - Microsoft SharePoint Server 2010

  - Microsoft SharePoint Foundation 2010

  - Microsoft InfoPath 2007 Service Pack 2

  - Microsoft InfoPath 2007 Service Pack 3

  - Microsoft InfoPath 2010 Service Pack 1

  - Microsoft Groove Server 2010 Service Pack 1

  - Microsoft Office Web Apps 2010 Service Pack 1

  - Microsoft SharePoint Server 2010 Service Pack 1

  - Microsoft SharePoint Foundation 2010 Service Pack 1

  - Microsoft Office SharePoint Server 2007 Service Pack 2

  - Microsoft Office SharePoint Server 2007 Service Pack 3

  - Microsoft Windows SharePoint Services 3.0 Service Pack 2");

  script_tag(name:"insight", value:"- Certain input is not properly sanitised in the 'SafeHTML' API before being
  returned to the user.

  - Certain unspecified input is not properly sanitised in scriptresx.ashx
    before being returned to the user. This can be exploited to execute
    arbitrary HTML and script code in a user's browser session in context of
    an affected site.

  - An error when validating search scope permissions can be exploited to view
    or modify another user's search scope.

  - Certain unspecified input associated with a username is not properly
    sanitised before being returned to the user. This can be exploited to
    execute arbitrary HTML and script code in a user's browser session in
    context of an affected site.

  - Certain unspecified input associated with a URL is not properly verified
    before being used to redirect users. This can be exploited to redirect a
    user to an arbitrary website.

  - Certain unspecified input associated with a reflected list parameter is
    not properly sanitised before being returned to the user. This can be
    exploited to execute arbitrary HTML and script code in a user's browser
    session in context of an affected site.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS12-050.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## InfoPath 2007 and InfoPath 2010
keys = make_list("SOFTWARE\Microsoft\Office\12.0\InfoPath\InstallRoot",
                 "SOFTWARE\Microsoft\Office\14.0\InfoPath\InstallRoot");
foreach key(keys)
{
  if(registry_key_exists(key:key))
  {
    infoPath = registry_get_sz(key:key, item:"Path");

    if(infoPath)
    {
      exeVer = fetch_file_version(sysPath:infoPath, file_name:"Infopath.Exe");
      dllVer = fetch_file_version(sysPath:infoPath, file_name:"Ipeditor.dll");
      if((exeVer &&
         (version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6661.4999") ||
          version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.6120.4999"))) ||
         (dllVer &&
         (version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6661.4999") ||
          version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6120.4999"))))
     {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

## Microsoft Groove 2010
exeVer = get_kb_item("SMB/Office/Groove/Version");
if(exeVer && exeVer =~ "^14\.")
{
  key = "SOFTWARE\Microsoft\Office Server\14.0\Groove";
  if(registry_key_exists(key:key))
  {
    dllPath =  registry_get_sz(key:key, item:"EMSInstallDir");
    if(dllPath)
    {
      dllVer = fetch_file_version(sysPath:dllPath, file_name:"groovems.dll");
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6116.4999")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

cpe_list = make_list("cpe:/a:microsoft:sharepoint_server", "cpe:/a:microsoft:sharepoint_foundation", "cpe:/a:microsoft:sharepoint_services");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

## SharePoint Server 2007 and 2010
if("cpe:/a:microsoft:sharepoint_server" >< cpe)
{
  ## SharePoint Server 2007 Service Pack 2 (coreserver)
  if(vers =~ "^12\."){
    key = "SOFTWARE\Microsoft\Office Server\12.0";
    file = "Microsoft.sharepoint.publishing.dll";
  }

  ## SharePoint Server 2010 (wosrv)
  else if(vers =~ "^14\."){
    key = "SOFTWARE\Microsoft\Office Server\14.0";
    file = "Microsoft.office.server.native.dll";
  }

  if(key && registry_key_exists(key:key) && file)
  {
    if(path = registry_get_sz(key:key, item:"BinPath"))
    {
      dllVer = fetch_file_version(sysPath:path, file_name:file);
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6660.4999") ||
           version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6108.4999")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

## SharePoint Foundation 2010
if("cpe:/a:microsoft:sharepoint_foundation" >< cpe)
{
  key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0";
  if(registry_key_exists(key:key))
  {
    dllPath = registry_get_sz(key:key, item:"Location");
    if(dllPath)
    {
      dllVer  = fetch_file_version(sysPath:dllPath, file_name:"BIN\Onetutil.dll");
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.6120.5004")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

## SharePoint Services 3.0 and 2.0
if("cpe:/a:microsoft:sharepoint_services" >< cpe)
{
  key = "SOFTWARE\Microsoft\Shared Tools";
  if(registry_key_exists(key:key))
  {
    dllPath =  registry_get_sz(key:key, item:"SharedFilesDir");
    if(dllPath)
    {
      dllVer = fetch_file_version(sysPath:dllPath, file_name:"web server extensions\12\BIN\Onetutil.dll");
      if(dllVer)
      {
        if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6661.4999")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }

      dllVer2 = fetch_file_version(sysPath:dllPath, file_name:"web server extensions\60\BIN\Onetutil.dll");
      if(dllVer2 && dllVer2 =~ "^11\.0")
      {
        if(version_is_less(version:dllVer2, test_version:"11.0.8346.0"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}


