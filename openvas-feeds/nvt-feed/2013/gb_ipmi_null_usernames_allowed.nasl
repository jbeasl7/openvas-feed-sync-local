# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103838");
  script_version("2024-07-05T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-05 05:05:40 +0000 (Fri, 05 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-11-26 12:23:03 +0100 (Tue, 26 Nov 2013)");
  # nb: A higher score than the attached CVE-2018-1668 is used here as the found account might have
  # not only read access (C:P/I:N) but also full write access (C:P/I:C).
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:N");

  script_cve_id("CVE-2018-1668");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("IPMI 'Null' Usernames Allowed (IPMI Protocol)");

  script_category(ACT_GATHER_INFO);

  script_family("General");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_ipmi_detect.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);
  script_mandatory_keys("ipmi/null_username");

  script_tag(name:"summary", value:"The remote Intelligent Platform Management Interface (IPMI)
  service allows 'null' usernames.");

  script_tag(name:"vuldetect", value:"Evaluates information gathered by the VT 'Intelligent Platform
  Management Interface (IPMI) Detection (IPMI Protocol)' (OID: 1.3.6.1.4.1.25623.1.0.103835).");

  script_tag(name:"affected", value:"All IPMI devices allowing accounts with a null username or
  password. The following products are known to be affected:

  - CVE-2018-1668: IBM Open Power Firmware OP910 and OP920

  Other devices / vendors might be affected as well.");

  script_tag(name:"solution", value:"Don't allow accounts with a null username or password. Please
  contact the vendor / consult the device manual for more information.");

  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi");
  script_xref(name:"URL", value:"http://fish2.com/ipmi/");
  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/security-bulletin-ibm-datapower-gateway-appliances-are-affected-vulnerability-ipmi-cve-2018-1668");
  script_xref(name:"URL", value:"https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");

port = service_get_port(default:623, ipproto:"udp", proto:"ipmi");

if (get_kb_item("ipmi/" + port + "/null_username")) {

  # nb:
  # - Store the reference from this one to gb_ipmi_detect.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail(name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.103835"); # gb_ipmi_detect.nasl
  register_host_detail(name:"detected_at", value:port + "/udp");

  report = "The remote IPMI service allows 'null' usernames.";
  security_message(port:port, proto:"udp", data:report);
  exit(0);
}

exit(99);
