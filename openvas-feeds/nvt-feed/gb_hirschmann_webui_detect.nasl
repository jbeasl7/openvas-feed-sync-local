# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140575");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-04 14:40:12 +0700 (Mon, 04 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Hirschmann Devices Detection (Web UI)");

  script_tag(name:"summary", value:"Detection of Hirschmann devices over HTTP.

The script sends a connection request to the server and attempts to detect Hirschmann devices and to extract
its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.hirschmann.com/en/Hirschmann_Produkte/index.phtml");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

known_platforms = make_list ("L2B", "L2E", "L2P", "L3E", "L3P", "HiOS-3S");

port = http_get_port(default: 443);
res = http_get_cache(port: port, item: "/");

if (res =~ "^HTTP/1\.[01] 200" &&
     ('VALUE="com.hirschmann.' >< res && 'productName' >< res) ||
     ("img/hirschLogo.gif" >< res && "GAI.SESSIONID" >< res)) {

  set_kb_item( name:"hirschmann_device/detected", value:TRUE );
  set_kb_item( name:"hirschmann_device/http/detected", value:TRUE );
  set_kb_item( name:"hirschmann_device/http/port", value:port );

  fw_version    = "unknown";
  product_name  = "unknown";
  platform_name = "unknown";

  # "productName" VALUE="MACH Switch
  # "productName" VALUE="MACH Rugged Switch
  # "productName" VALUE="MICE
  # "productName" VALUE="MACH 4002
  prod_name = eregmatch(pattern: '"productName" VALUE="([^"]+)', string: res);
  if (isnull(prod_name[1])) {
    prod_name = eregmatch(pattern: "<title>([^<]+)", string: res);
    if (!isnull(prod_name[1]))
      product_name = prod_name[1];
      concluded += prod_name[0] + '\n';
  } else {
    product_name = prod_name[1];
    concluded += prod_name[0] + '\n';
  }

  # "productVersion" VALUE="09.0.11
  vers = eregmatch(pattern: '"productVersion" VALUE="([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    fw_version = vers[1];
    concluded += vers[0] + '\n';
  }

  # "launchClass" VALUE="com.hirschmann.products.apps.marL2P.marL2P_Main
  # "launchClass" VALUE="com.hirschmann.products.apps.rsrL2P.rsrL2P_Main
  pltf_name = egrep(pattern: '"launchClass" VALUE="com\\.hirschmann\\.products\\.apps\\.', string: res);
  if (!isnull(pltf_name)) {
    foreach known_platform (known_platforms) {
      if (known_platform >< pltf_name) {
        platform_name = known_platform;
        break;
      }
    }
    concluded += pltf_name + '\n';
  }

  set_kb_item(name: "hirschmann_device/http/" + port + "/fw_version", value: fw_version);
  set_kb_item(name: "hirschmann_device/http/" + port + "/product_name", value: product_name);
  set_kb_item(name: "hirschmann_device/http/" + port + "/platform_name", value: platform_name);

  if (concluded)
    set_kb_item(name: "hirschmann_device/http/" + port + "/concluded", value: concluded);
}

exit(0);
