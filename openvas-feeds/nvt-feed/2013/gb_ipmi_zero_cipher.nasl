# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103840");
  script_version("2024-08-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-08-13 05:05:46 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"creation_date", value:"2013-11-27 15:03:17 +0100 (Wed, 27 Nov 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2013-4782", "CVE-2013-4783", "CVE-2013-4784", "CVE-2014-2955");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IPMI Cipher Suite 0 (Cipher Zero) Authentication Bypass Vulnerability (IPMI Protocol)");

  script_category(ACT_ATTACK);

  script_family("General");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_ipmi_detect.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);
  script_mandatory_keys("ipmi/version/2.0");

  script_tag(name:"summary", value:"Intelligent Platform Management Interface (IPMI) services are
  prone to an authentication bypass vulnerability through the use of cipher suite 0 (aka cipher
  zero).");

  script_tag(name:"vuldetect", value:"Sends a request with a zero cipher and checks if this request
  was accepted.");

  script_tag(name:"insight", value:"The remote IPMI service accepted a session open request for
  cipher suite 0 (aka cipher zero).");

  script_tag(name:"impact", value:"Attackers can exploit this issue to gain administrative access to
  the device and disclose sensitive information.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - Supermicro BMC implementation

  - Dell iDRAC6 with firmware 1.x before 1.92 and 2.x and 3.x before 3.42, and iDRAC7 with firmware
  before 1.23.23

  - HP Integrated Lights-Out (iLO) BMC implementation

  - Raritan PX before 1.5.11 on DPXR20A-16 devices

  Other versions or vendors might be affected as well.");

  script_tag(name:"solution", value:"- Supermicro has released fixes for its BMC firmware, please
  see the references for more info

  - For other vendors: Ask the Vendor for an update / more information

  - Disable the usage of cipher suite 0 by following vendor instructions

  Please contact the vendor of the remote device for more information.");

  script_xref(name:"URL", value:"http://fish2.com/ipmi/cipherzero.html");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi");
  script_xref(name:"URL", value:"http://fish2.com/ipmi/");
  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2014/Jul/14");
  script_xref(name:"URL", value:"https://www.dell.com/support/kbdoc/en-US/000135423/how-to-check-if-ipmi-cipher-0-is-off");
  script_xref(name:"URL", value:"https://www.supermicro.com/support/faqs/faq.cfm?faq=16536");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");

port = service_get_port(default:623, ipproto:"udp", proto:"ipmi");

if(!soc = open_sock_udp(port))
  exit(0);

req = raw_string(0x06, 0x00, 0xff, 0x07, 0x06, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x71, 0x1e, 0x24, 0x73, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
                 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00);

send(socket:soc, data:req);
recv = recv(socket:soc, length:1024);
close(soc);

if(hexstr(recv) !~ "0600ff07" || strlen(recv) < 16 || hexstr(recv[5]) != "11")
  exit(0);

len = ord(raw_string(recv[14], recv[15]));
if(len > strlen(recv))
  exit(0);

data = substr(recv, strlen(recv) - len);
if(data[1] && ord(data[1]) == 0) {

  # nb:
  # - Store the reference from this one to gb_ipmi_detect.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail(name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.103835"); # gb_ipmi_detect.nasl
  register_host_detail(name:"detected_at", value:port + "/udp");

  report = "The remote IPMI service accepted a session open request for cipher zero.";
  security_message(port:port, proto:"udp", data:report);
  exit(0);
}

exit(99);
