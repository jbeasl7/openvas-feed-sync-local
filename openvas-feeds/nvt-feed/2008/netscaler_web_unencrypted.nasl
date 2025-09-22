# SPDX-FileCopyrightText: 2008 nnposter
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:citrix:netscaler";

if (description){
  script_oid("1.3.6.1.4.1.25623.1.0.80026");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Unencrypted NetScaler Web Management Interface (HTTP)");

  script_family("Web Servers");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 nnposter");
  script_dependencies("gb_citrix_netscaler_consolidation.nasl", "gb_ssl_tls_version_get.nasl");
  script_mandatory_keys("citrix/netscaler/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Consider disabling this port completely and using only HTTPS.");

  script_tag(name:"summary", value:"The remote web management interface does not encrypt connections.

Description :

The remote Citrix NetScaler web management interface does use TLS or
SSL to encrypt connections.");

  script_tag(name:"qod_type", value:"general_note");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("host_details.inc");
include("ssl_funcs.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

if (!tls_ssl_is_enabled(port: port))
  security_message(port: port);

exit(0);
