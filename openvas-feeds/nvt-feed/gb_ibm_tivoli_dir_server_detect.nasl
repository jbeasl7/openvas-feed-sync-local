# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801812");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IBM Tivoli Directory Server Detection (LDAP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"summary", value:"LDAP based detection of IBM Tivoli Directory Server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ldap.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ldap_get_port( default:389 );

# nb: LDAP searchMessage Request Payload
req = raw_string(0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, 0x02, 0x01,
                 0x0e, 0x63, 0x84, 0x00, 0x00, 0x00, 0x24, 0x04,
                 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02,
                 0x01, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x00,
                 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
                 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x84, 0x00,
                 0x00, 0x00, 0x00);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

send(socket:soc, data:req);
result = recv(socket:soc, length:2000);
close(soc);

if("International Business Machines" >< result && "ibmdirectoryversion1" >< result) {
  index = stridx(result, "ibmdirectoryversion1");
  if(index == -1)
    exit(0);

  install = port + "/tcp";
  version = "unknown";

  vers = substr(result, index + 22, index + 36);
  len = strlen(vers);
  for(i = 0; i < len; i++) {
    if(vers[i] =~ '[0-9.]') {
      tdsVer = tdsVer + vers[i];
    }
  }

  if(tdsVer) {
    version = tdsVer;
    concl = vers;
    set_kb_item(name:"IBM/TDS/Ver", value:version);
  }

  cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:ibm:tivoli_directory_server:");
  if(!cpe)
    cpe = "cpe:/a:ibm:tivoli_directory_server";

  register_product(cpe:cpe, location:install, port:port, service:"ldap");

  log_message(data:build_detection_report(app:"IBM Tivoli Directory Server",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:vers),
              port:port);
}

exit(0);
