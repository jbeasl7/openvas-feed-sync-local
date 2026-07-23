# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902220");
  script_version("2026-07-22T06:26:54+0000");
  script_tag(name:"last_modification", value:"2026-07-22 06:26:54 +0000 (Wed, 22 Jul 2026)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cyrus IMAP Server Detection (IMAP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("imap4_banner.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/cyrus/detected");

  script_tag(name:"summary", value:"IMAP based detection of Cyrus IMAP Server.");

  exit(0);
}

include("host_details.inc");
include("imap_func.inc");
include("port_service_func.inc");

port = imap_get_port(default: 143);

if (!banner = imap_get_banner(port: port))
  exit(0);

# * OK [CAPABILITY IMAP4rev1 LITERAL+ ID ENABLE STARTTLS AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5 AUTH=DIGEST-MD5 SASL-IR] example.com Cyrus IMAP v2.4.17 server ready
# * OK [CAPABILITY IMAP4rev1 LITERAL+ ID ENABLE STARTTLS AUTH=PLAIN SASL-IR] example.com Cyrus IMAP 3.0.7-24.el8 Fedora server ready
if ("Cyrus IMAP" >!< banner || "server ready" >!< banner)
  exit(0);

version = "unknown";

set_kb_item(name: "cyrus/imap_server/detected", value: TRUE);
set_kb_item(name: "cyrus/imap_server/imap/detected", value: TRUE);
set_kb_item(name: "cyrus/imap_server/imap/port", value: port);
set_kb_item(name: "cyrus/imap_server/imap/" + port + "/concluded", value: banner);

# * OK lxmail Cyrus IMAP4 v2.1.18-IPv6-Debian-2.1.18-5.1 server ready
# nb: IMAP currently exists in version 2-4 with 2 having an optional "bis" suffix
vers = eregmatch(pattern: "IMAP([0-9](bis)?)? v?([0-9.]+)", string: banner);
if (isnull(vers[3])) {
  # ID ("name" "Cyrus IMAPD" "version" "2.5.10-Debian-2.5.10-3+deb9u1 be9a1799 2016-10-18" "vendor" "Project Cyrus"
  vers = eregmatch(pattern: '"version" "([0-9.]+)', string: banner);
  if (!isnull(vers[1]))
    version = vers[1];
} else {
  version = vers[3];
}

set_kb_item(name: "cyrus/imap_server/imap/" + port + "/version", value: version);

exit(0);
