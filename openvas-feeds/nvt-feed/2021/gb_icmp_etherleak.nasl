# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146546");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2021-08-23 14:16:29 +0000 (Mon, 23 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-10 14:11:00 +0000 (Fri, 10 May 2019)");

  script_cve_id("CVE-2003-0001", "CVE-2013-4690", "CVE-2017-2304", "CVE-2018-0014",
                "CVE-2021-3031", "CVE-2022-22216");

  script_tag(name:"qod_type", value:"remote_probe");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ICMP 'Etherleak' Information Disclosure");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("host_alive_detection.nasl", "os_fingerprint.nasl", "global_settings.nasl");
  script_mandatory_keys("keys/islocalnet");
  script_exclude_keys("keys/islocalhost", "keys/TARGET_IS_IPV6", "ICMPv4/EchoRequest/failed");

  script_tag(name:"summary", value:"The remote host is prone to an information disclosure
  vulnerability over ICMP dubbed 'Etherleak'.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted ICMP packets and checks the responses.");

  script_tag(name:"insight", value:"Multiple ethernet Network Interface Card (NIC) device drivers
  do not pad frames with null bytes, which allows remote attackers to obtain information from
  previous packets or kernel memory by using malformed packets, as demonstrated by Etherleak.");

  script_tag(name:"impact", value:"An unauthenticated attacker might gather sensitive information.");

  script_tag(name:"affected", value:"The following products / devices are known to be affected (Some
  have vendor specific CVEs):

  - Original CVE-2003-0001:

  * Multiple unnamed ethernet Network Interface Card (NIC) device drivers

  * The Linux Kernel on at least Debian

  * FreeBSD and NetBSD

  * Windows 2000

  * Cisco Adaptive Security Appliance (ASA, CSCua88376)

  * HP-UX network device drivers (HPSBUX0305-261)

  - CVE-2013-4690, JSA10579: Juniper Networks Junos OS on SRX1400, SRX3400 and SRX3600 devices

  - CVE-2017-2304, JSA10773: Juniper Networks Junos OS on QFX3500, QFX3600, QFX5100, QFX5200, EX4300
  and EX4600 Series devices

  - CVE-2018-0014, JSA10841: Juniper Networks ScreenOS devices

  - CVE-2021-3031, PAN-124681: Palo Alto PAN-OS on PA-200, PA-220, PA-500, PA-800, PA-2000 Series,
  PA-3000 Series, PA-3200 Series, PA-5200 Series, and PA-7000 Series firewalls

  - CVE-2022-22216, JSA69720: Juniper Networks Junos OS on PTX and QFX10k Series devices

  Other products / devices might be affected as well.");

  script_tag(name:"solution", value:"Contact the vendor of the network device driver for a solution.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20050924092427/http://www.atstake.com/research/advisories/2003/a010603-1.txt");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/412115");
  script_xref(name:"URL", value:"https://dl.packetstormsecurity.net/advisories/atstake/atstake_etherleak_report.pdf");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/3555");
  script_xref(name:"URL", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCua88376");
  script_xref(name:"URL", value:"https://www.ciscozine.com/cisco-asa-8-4-4-68-2-5-32-ethernet-information-leak/");
  script_xref(name:"URL", value:"https://security.paloaltonetworks.com/CVE-2021-3031");
  script_xref(name:"URL", value:"https://supportportal.juniper.net/s/article/2022-07-Security-Bulletin-Junos-OS-PTX-Series-and-QFX10000-Series-Etherleak-memory-disclosure-in-Ethernet-padding-data-CVE-2022-22216");
  script_xref(name:"URL", value:"https://supportportal.juniper.net/s/article/2018-01-Security-Bulletin-ScreenOS-Etherleak-vulnerability-found-on-ScreenOS-device-CVE-2018-0014");
  script_xref(name:"URL", value:"https://supportportal.juniper.net/s/article/2017-01-Security-Bulletin-QFX3500-QFX3600-QFX5100-QFX5200-EX4300-and-EX4600-Etherleak-memory-disclosure-in-Ethernet-padding-data-CVE-2017-2304");
  script_xref(name:"URL", value:"https://supportportal.juniper.net/s/article/2013-07-Security-Bulletin-Junos-SRX1400-3400-3600-vulnerable-to-Etherleak-packet-fragment-disclosure-in-Ethernet-padding-data-CVE-2013-4690");

  exit(0);
}

include("dump.inc");
include("list_array_func.inc");

if (TARGET_IS_IPV6() || islocalhost())
  exit(0);

if (!islocalnet())
  exit(0);

if (get_kb_item("ICMPv4/EchoRequest/failed"))
  exit(0);

own_ip = this_host();
target_ip = get_host_ip();

icmp_ping_request = 8;
icmp_ping_reply = 0;
icmp_id = rand() % 65536;

ip = forge_ip_packet(ip_hl: 5, ip_v: 4, ip_off: 0, ip_id: 9, ip_tos: 0, ip_p: IPPROTO_ICMP,
                     ip_len: 46, ip_src: own_ip, ip_ttl: 255);
icmp = forge_icmp_packet(ip: ip, icmp_type: icmp_ping_request, icmp_code: 0, icmp_seq: 1, icmp_id: icmp_id,
                         data: "X");

filter = string("icmp and src host ", target_ip, " and dst host ", own_ip, " and icmp[0:1] = ",
                icmp_ping_reply);

nonnull = make_list();

for (i = 0; i < 5; i++) {
  recv = send_packet(icmp, pcap_active: TRUE, pcap_filter: filter, pcap_timeout: 3);

  if (!recv)
    continue;

  data = get_icmp_element(icmp: recv, element: "data");

  if (data && data[0] == "X") {
    # The data might include the VLAN tag (4 bytes) which we will not check
    # see e.g. https://www.ibm.com/support/pages/ibm-aix-my-system-vulnerable-etherleak-cve-2003-0001
    padding = substr(data, 1, strlen(data) - 4);
    nonnull_padding = str_replace(string: padding, find: raw_string(0x00), replace: "");
    if (strlen(nonnull_padding) != 0) {
      nonnull = make_list(nonnull, nonnull_padding);
      report += '\n\n' + hexdump(ddata: data);
    }
  }
}

nonnull = make_list_unique(nonnull);

if (max_index(nonnull) > 1) {
  report = "Non-null padding observed in the following data frames:" + report;
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
