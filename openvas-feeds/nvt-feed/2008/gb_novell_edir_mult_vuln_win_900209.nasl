# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900209");
  script_version("2025-04-16T05:39:43+0000");
  script_tag(name:"last_modification", value:"2025-04-16 05:39:43 +0000 (Wed, 16 Apr 2025)");
  script_tag(name:"creation_date", value:"2008-09-02 16:25:07 +0200 (Tue, 02 Sep 2008)");
  script_cve_id("CVE-2008-5091", "CVE-2008-5092", "CVE-2008-5093", "CVE-2008-5094", "CVE-2008-5095");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("General");
  script_name("Novell eDirectory Multiple Vulnerabilities - Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/31684");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30947");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020788.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020787.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020786.html");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Aug/1020785.html");
  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=RH_B5b3M6EQ~");

  script_tag(name:"summary", value:"Novell eDirectory is prone to cross-site scripting (XSS), denial
  of service (DoS) and remote code execution (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - errors in HTTP Protocol Stack that can be exploited to cause heap based buffer overflow via a
  specially crafted language/content-length headers.

  - input passed via unspecified parameters to the HTTP Protocol Stack is not properly sanitzed
  before being returned to the user.

  - Multiple unknown errors exist in LDAP and NDS services.");

  script_tag(name:"affected", value:"Novell eDirectory 8.8 SP2 and prior versions on Windows
  2000/2003.");

  script_tag(name:"solution", value:"Apply 8.8 Service Pack 3.");

  script_tag(name:"impact", value:"Successful Remote exploitation will allow execution of arbitrary
  code, heap-based buffer overflow, Cross Site Scripting attacks, or cause memory corruption.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion"))
  exit(0);

eDirVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NDSonNT", item:"DisplayName");
if(!eDirVer)
  exit(0);

if(!(egrep(pattern:"^Novell eDirectory ([0-7]\..*|8\.[0-7]( .*)?|8\.8( SP[0-2])?)$", string:eDirVer)))
  exit(0);

eDirPath = registry_get_sz(key:"SOFTWARE\NOVELL\NDS\NDSSNMPAgent\CurrentVersion", item:"Pathname");
if(!eDirPath)
  exit(0);

eDirPath = eDirPath - "ndssnmpsa.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:eDirPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:eDirPath + "nauditds.dlm");

name   =  kb_smb_name();
login  =  kb_smb_login();
pass   =  kb_smb_password();
domain =  kb_smb_domain();
port   =  kb_smb_transport();

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

if( ! get_kb_item( "login/SMB/kerberos/success" ) ) {
  info = smb_login_and_get_tid_uid(soc:soc, name:name, login:login, passwd:pass, domain:domain, share:share);
} else {
  kdc = kb_smb_kdc();
  host = kb_smb_hostname();
  info = smb_login_and_get_tid_uid(soc:soc, name:name, login:login, passwd:pass, domain:domain, share:share, kdc:kdc, host:host );
}

if(isnull(info)) {
 close(soc);
 exit(0);
}

uid = info["uid"];
tid = info["tid"];

fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
if(!fid) {
  close(soc);
  exit(0);
}

fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
close(soc);
if(!fsize)
  exit(0);

if(fsize < 110592) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
