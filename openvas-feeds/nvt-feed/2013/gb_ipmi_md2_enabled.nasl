# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103839");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"creation_date", value:"2013-11-26 12:33:03 +0100 (Tue, 26 Nov 2013)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("IPMI MD2 Auth Type Support Enabled (IPMI Protocol)");

  script_category(ACT_GATHER_INFO);

  script_family("General");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("gb_ipmi_detect.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);
  script_mandatory_keys("ipmi/md2_supported");

  script_tag(name:"summary", value:"The remote Intelligent Platform Management Interface (IPMI)
  service has MD2 auth type support enabled.");

  script_tag(name:"vuldetect", value:"Evaluates information gathered by the VT 'Intelligent Platform
  Management Interface (IPMI) Detection (IPMI Protocol)' (OID: 1.3.6.1.4.1.25623.1.0.103835).");

  script_tag(name:"solution", value:"Disable MD2 auth type support. Please contact the vendor /
  consult the device manual for more information.");

  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi");
  script_xref(name:"URL", value:"http://fish2.com/ipmi/");

  exit(0);
}

include("port_service_func.inc");
include("host_details.inc");

port = service_get_port(default:623, ipproto:"udp", proto:"ipmi");

if (get_kb_item("ipmi/" + port + "/md2_supported")) {

  # nb:
  # - Store the reference from this one to gb_ipmi_detect.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail(name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.103835"); # gb_ipmi_detect.nasl
  register_host_detail(name:"detected_at", value:port + "/udp");

  report = "The remote IPMI service has MD2 auth type support enabled.";
  security_message(port:port, proto:"udp", data:report);
  exit(0);
}

exit(99);
