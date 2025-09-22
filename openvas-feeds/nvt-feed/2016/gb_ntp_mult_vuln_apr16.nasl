# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807567");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976",
                "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138",
                "CVE-2015-8139", "CVE-2015-8140", "CVE-2015-8158", "CVE-2016-1547",
                "CVE-2016-1548", "CVE-2015-7705", "CVE-2016-1550", "CVE-2016-1551",
                "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519",
                "CVE-2015-7704");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 13:15:00 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"creation_date", value:"2016-04-28 15:41:24 +0530 (Thu, 28 Apr 2016)");
  script_name("NTP.org 'ntpd' Multiple Vulnerabilities (Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/718152");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The ntpd does not filter IPv4 bogon packets received from the network.

  - The duplicate IPs on unconfig directives will cause an assertion botch.

  - Crafted addpeer with hmode > 7 causes array wraparound with MATCH_ASSOC.

  - An improper Restriction of Operations within the Bounds of a Memory Buffer.

  - Replay attack on authenticated broadcast mode.

  - The nextvar() function does not properly validate length.

  - The ntpq saveconfig command allows dangerous characters in filenames.

  - Restriction list NULL pointer dereference.

  - Uncontrolled Resource Consumption in recursive traversal of restriction list.

  - An off-path attacker can send broadcast packets with bad authentication to
  broadcast clients.

  - An improper sanity check for the origin timestamp.

  - Origin Leak: ntpq and ntpdc Disclose Origin Timestamp to Unauthenticated Clients.

  - The sequence number being included under the signature fails to prevent
  replay attacks in ntpq protocol.

  - An uncontrolled Resource Consumption in ntpq.

  - An off-path attacker can deny service to ntpd clients by demobilizing
  preemptible associations using spoofed crypto-NAK packets.

  - Multiple input validation errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  unauthenticated remote attackers to spoof packets to cause denial of service,
  authentication bypass, or certain configuration changes.");

  script_tag(name:"affected", value:"NTPd version prior to 4.2.8p7.");

  script_tag(name:"solution", value:"Update to version 4.2.8p7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if (revcomp(a: version, b: "4.2.8p7") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.8p7", install_path: location);
  security_message(port: port, proto: proto, data: report);
  exit(0);
}

exit(99);
