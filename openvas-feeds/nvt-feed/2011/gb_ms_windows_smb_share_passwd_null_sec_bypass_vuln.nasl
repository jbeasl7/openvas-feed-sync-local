# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801991");
  script_version("2025-04-16T05:39:43+0000");
  script_cve_id("CVE-1999-0519", "CVE-1999-0520", "CVE-2002-1117");
  script_tag(name:"last_modification", value:"2025-04-16 05:39:43 +0000 (Wed, 16 Apr 2025)");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Microsoft Windows SMB/NETBIOS NULL Session Authentication Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Windows");
  script_dependencies("netbios_name_get.nasl", "smb_nativelanman.nasl", "os_detection.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("SMB/samba", "login/SMB/kerberos/success");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/1");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/2");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/3");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/10093");
  script_xref(name:"URL", value:"https://seclab.cs.ucdavis.edu/projects/testing/vulner/36.html");
  script_xref(name:"URL", value:"https://seclab.cs.ucdavis.edu/projects/testing/vulner/38.html");

  script_tag(name:"summary", value:"Microsoft Windows is prone to an authentication bypass
  vulnerability via SMB/NETBIOS.");

  script_tag(name:"vuldetect", value:"Send multiple crafted SMB requests to various shares and
  checks the responses.");

  script_tag(name:"insight", value:"The flaw is due to an SMB share, allows full access to Guest
  users. If the Guest account is enabled, anyone can access the computer without a valid user
  account or password.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to use shares to
  cause the system to crash.");

  script_tag(name:"affected", value:"- Microsoft Windows 95

  - Microsoft Windows 98

  - Microsoft Windows NT

  - Microsoft Windows 2000

  - Microsoft Windows in other implementations / versions might be affected as well");

  script_tag(name:"solution", value:"A workaround is to:

  - Disable null session login

  - Remove the share

  - Enable passwords on the share");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");

if(kb_smb_is_samba())
  exit(0);

port = kb_smb_transport();
if(!port)
  port = 139;

if(!get_port_state(port))
  exit(0);

name = "*SMBSERVER";

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

r = smb_session_request(soc:soc, remote:name);
if(!r) {
  close(soc);
  exit(0);
}

prot = smb_neg_prot(soc:soc);
if(!prot) {
  close(soc);
  exit(0);
}

r = smb_session_setup(soc:soc, login:"", password:"", domain:"", prot:prot);
if(!r) {
  r = smb_session_setup(soc:soc, login:"anonymous", password:"", domain:"", prot:prot);
  if(!r) {
    close(soc);
    exit(0);
  } else {
    creds = "with the 'anonymous' login and an empty password.";
  }
} else {
  creds = "with an empty login and password.";
}

uid = session_extract_uid(reply:r);
if(!uid) {
  close(soc);
  exit(0);
}

foreach s(make_list("A$", "C$", "D$", "ADMIN$", "WINDOWS$", "ROOT", "WINNT$", "IPC$")) {
  r = smb_tconx(soc:soc, name:name, uid:uid, share:s);
  if(r) {
    tid = tconx_extract_tid(reply:r);
    if(tid) {
      close(soc);
      report = "It was possible to login at the share '" + s + "' " + creds;
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

if(soc) close(soc);
exit(99);
