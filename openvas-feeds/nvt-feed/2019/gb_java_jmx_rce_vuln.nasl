# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143207");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2019-12-02 10:02:20 +0000 (Mon, 02 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Java JMX Insecure Configuration Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("General");
  script_dependencies("gb_rmi_registry_detect.nasl");
  script_require_ports("Services/rmi_registry", 1099);
  script_mandatory_keys("rmi_registry/detected");

  script_tag(name:"summary", value:"The Java JMX interface is configured in an insecure way by
  allowing unauthenticated attackers to load classes from any remote URL.");

  script_tag(name:"vuldetect", value:"Sends crafted RMI requests and checks the responses.");

  script_tag(name:"solution", value:"Enable password authentication and/or SSL client certificate
  authentication for the JMX agent.");

  script_xref(name:"URL", value:"https://mogwailabs.de/blog/2019/04/attacking-rmi-based-jmx-services/");
  script_xref(name:"URL", value:"https://www.optiv.com/blog/exploiting-jmx-rmi");
  script_xref(name:"URL", value:"https://www.rapid7.com/db/modules/exploit/multi/misc/java_jmx_server");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("port_service_func.inc");
include("rmi_func.inc");

function rmi_parse_res(data) {
  local_var data, port, obj_id, result, class, rmi_classes, class_found;

  result = make_array();

  rmi_classes = make_list("javax.management.remote.rmi.RMIConnectionImpl",
                          "javax.management.remote.rmi.RMIConnectionImpl_Stub",
                          "javax.management.remote.rmi.RMIConnector",
                          "javax.management.remote.rmi.RMIConnectorServer",
                          "javax.management.remote.rmi.RMIIIOPServerImpl",
                          "javax.management.remote.rmi.RMIJRMPServerImpl",
                          "javax.management.remote.rmi.RMIServerImpl",
                          "javax.management.remote.rmi.RMIServerImpl_Stub",
                          "javax.management.remote.rmi.RMIConnection",
                          "javax.management.remote.rmi.RMIServer");

  if ("javax.management.remote.rmi" >!< data || "UnicastRef" >!< data)
    return NULL;

  foreach class (rmi_classes) {
    if (raw_string(class, 0x00) >< data) {
      class_found = TRUE;
      break;
    }
  }

  if (!class_found)
    return NULL;

  data = strstr(data, "UnicastRef");
  if (strlen(data) < 37)
    return NULL;

  pos = 10;
  if ("UnicastRef2" >< data)
    pos += 2;

  len = getword(blob: data, pos: pos);
  pos += len + 4;

  port = getword(blob: data, pos: pos);
  pos += 2;
  obj_id = substr(data, pos, pos + 21);
  result["port"] = port;
  result["obj_id"] = obj_id;

  return result;
}

port = service_get_port(default: 1099, proto: "rmi_registry");

if (!soc = open_sock_tcp(port))
  exit(0);

if (!rmi_connect(socket: soc)) {
  close(soc);
  exit(0);
}

recv = rmi_lookup(socket: soc, obj_name: "jmxrmi");

close(soc);

if (!recv)
  exit(0);

# Parse for the endpoint (RMI port, Object ID)
info = rmi_parse_res(data: recv);
if (isnull(info))
  exit(0);

rmi_port = info["port"];
obj_id = info["obj_id"];

soc = open_sock_tcp(rmi_port);
if (!soc)
  exit(0);

if (!rmi_connect(socket: soc)) {
  close(soc);
  exit(0);
}

data = raw_string(obj_id, 0xff, 0xff, 0xff, 0xff, 0xf0, 0xe0, 0x74, 0xea, 0xad, 0x0c, 0xae, 0xa8);
req = raw_string(0x50, 0xac, 0xed, 0x00, 0x05, 0x77, mkbyte(strlen(data)), data, 0x70);

send(socket: soc, data: req);
recv = recv(socket: soc, length: 8192, min: 2);

close(soc);

if ("javax.management.remote.rmi.RMIConnectionImpl_Stub" >< recv && "Exception" >!< recv) {
  report = "It was possible to call 'javax.management.remote.rmi.RMIServer.newClient' on the RMI port " + rmi_port +
           "/tcp without providing any credentials.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
