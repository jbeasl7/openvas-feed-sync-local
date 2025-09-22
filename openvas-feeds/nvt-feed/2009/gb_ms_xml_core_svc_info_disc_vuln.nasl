# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900314");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-0419");
  script_name("Microsoft XML Core Service Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://www.mindedsecurity.com/MSA01240108.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33803");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=380418");
  script_xref(name:"URL", value:"http://msdn.microsoft.com/hi-in/xml/default(en-us).aspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("smb_reg_service_pack.nasl", "secpod_ms_office_detection_900025.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to get sensitive information
  from cookies and corrupt the session state.");

  script_tag(name:"affected", value:"Microsoft, XML Core Service version 3.0/4.0/5.0/6.0 on Windows (all)");

  script_tag(name:"insight", value:"Microsoft XML Core Service fails to properly restrict access from the web
  pages to Set-Cookie2 HTTP response headers via XMLHttpRequest calls, which
  are related to the HTTPOnly protection mechanism.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft XML Core Service is prone to an information disclosure vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.microsoft.com");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup", item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file6 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml6.dll");
file6r = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml6r.dll");
file4 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml4.dll");
file4a = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml4a.dll");
file4r = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml4r.dll");
file3 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\msxml3.dll");

officeVer = get_kb_item("MS/Office/Ver");

# Microsoft Office 2003 & 2007
if((officeVer && officeVer =~ "^1[12]\.")||
   registry_key_exists(key:"SOFTWARE\Microsoft\Office"))
{
  dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Shared Tools", item:"SharedFilesDir");
  if(dllPath)
  {
    share2 = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
    file5 = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                         string:dllPath + "OFFICE11\msxml5.dll");
  }
}

# MSXML6.dll <= 6.20.1099.0
if(!isnull(file6) && !isnull(share))
{
  dll6Ver = GetVer(file:file6, share:share);
  if(dll6Ver != NULL)
  {
    if(version_is_less_equal(version:dll6Ver, test_version:"6.20.1099.0"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

# MSXML6r.dll <= 6.0.3883.0
if(!isnull(file6r) && !isnull(share))
{
  dll6rVer = GetVer(file:file6r, share:share);
  if(dll6rVer != NULL)
  {
    if(version_is_less_equal(version:dll6rVer, test_version:"6.0.3883.0"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

# MSXML5.dll <= 5.20.1087.0
if(!isnull(file5) && !isnull(share2))
{
  dll5Ver = GetVer(file:file5, share:share2);
  if(dll5Ver != NULL)
  {
    if(version_is_less_equal(version:dll5Ver, test_version:"5.20.1087.0"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

# MSXML4.dll <= 4.20.9870.0
if(!isnull(file4) && !isnull(share))
{
  dll4Ver = GetVer(file:file4, share:share);
  if(dll4Ver != NULL)
  {
    if(version_is_less_equal(version:dll4Ver, test_version:"4.20.9870.0"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

# MSXML4A.dll <= 4.10.9404.0
if(!isnull(file4a) && !isnull(share))
{
  dll4aVer = GetVer(file:file4a, share:share);
  if(dll4aVer != NULL)
  {
    if(version_is_less_equal(version:dll4aVer, test_version:"4.10.9404.0"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

# MSXML4R.dll <= 4.10.9404.0
if(!isnull(file4r) && !isnull(share))
{
  dll4rVer = GetVer(file:file4r, share:share);
  if(dll4rVer != NULL)
  {
    if(version_is_less_equal(version:dll4rVer, test_version:"4.10.9404.0"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

# MSXML3.dll <= 8.100.1048.0
if(!isnull(file3) && !isnull(share))
{
  dll3Ver = GetVer(file:file3, share:share);
  if(dll3Ver != NULL)
  {
    if(version_is_less_equal(version:dll3Ver, test_version:"8.100.1048.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
