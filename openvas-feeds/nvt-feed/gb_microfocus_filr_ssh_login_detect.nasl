# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105824");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-25 16:02:26 +0200 (Mon, 25 Jul 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Micro Focus (Novell) Filr Detection (SSH Login)");

  script_tag(name:"summary", value:"SSH login-based detection of Micro Focus (Novell) Filr.");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("filr/ssh/rls");

  exit(0);
}

include("host_details.inc");

if (!rls = get_kb_item("filr/ssh/rls"))
  exit(0);

if ("Filr" >!< rls)
  exit(0);

port = get_kb_item("filr/ssh/port");

version = "unknown";

set_kb_item(name: "microfocus/filr/detected", value: TRUE);
set_kb_item(name: "microfocus/filr/ssh-login/port", value: port);
set_kb_item(name: "microfocus/filr/ssh-login/" + port + "/concluded", value: chomp(rls));

# product=Novell Filr Appliance
# singleWordProductName=Filr
# version=2.0.0.421
# arch=x86_64
# id=filr-appliance
#
# product=Filr Appliance
# singleWordProductName=Filr
# version=4.0.0.155
# arch=x86_64
# id=filr-appliance
# updateRegcodeKey=regcode-filr
# updateProductName=Filr4.0
vers = eregmatch(pattern: "version=([0-9.]+)", string: rls);
if (!isnull(vers[1]))
  version = vers[1];

set_kb_item(name: "microfocus/filr/ssh-login/" + port + "/version", value: version);

exit(0);
