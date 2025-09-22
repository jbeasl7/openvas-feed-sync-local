# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:amx:netlinx_controller";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114080");
  script_version("2025-04-29T05:39:55+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-04-29 05:39:55 +0000 (Tue, 29 Apr 2025)");
  script_tag(name:"creation_date", value:"2019-03-08 13:36:06 +0100 (Fri, 08 Mar 2019)");

  # nb: No attacking request (just using previously gathered info) so no ACT_ATTACK
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Default Accounts");
  script_name("NetLinx Controller Unprotected Access (Telnet)");

  # nb: No need to disable via default_credentials/disable_default_account_checks or
  # gb_default_credentials_options.nasl because this isn't doing any login...
  script_dependencies("gb_netlinx_telnet_detect.nasl");
  script_mandatory_keys("netlinx/telnet/unprotected");

  script_tag(name:"summary", value:"The NetLinx Controller is accessible via an unprotected Telnet
  connection.");

  script_tag(name:"vuldetect", value:"Checks if credentials are required to access the device.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker to configure and
  control the device.");

  script_tag(name:"solution", value:"Disable the telnet access or protect it via a strong
  password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

# nb: Don't exit via islocalhost() or is_private_lan() here as such a system should be definitely
# access protected.

include("host_details.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

if(get_kb_item("netlinx/telnet/" + port + "/unprotected")) {
  report = "The Telnet access of this NetLinx Controller on port " + port + " is unprotected.";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
