# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xiongmai:net_surveillance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114081");
  script_version("2025-03-19T05:38:35+0000");
  # nb: This has been assigned by the Distributed Weakness Filing (DWF) Project but seems never was
  # really published due to some problems with the scope of that project (see relevant news around
  # this). We still have added it here for tracking / references purposes as it is actually
  # referenced via various sources.
  script_cve_id("CVE-2016-1000246");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-03-19 05:38:35 +0000 (Wed, 19 Mar 2025)");
  script_tag(name:"creation_date", value:"2019-03-12 13:52:47 +0100 (Tue, 12 Mar 2019)");
  # nb: Only direct file access, no ACT_ATTACK required
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_name("HangZhou XiongMai Technologies Net Surveillance 'DVR.html' Authentication Bypass Vulnerability");
  script_dependencies("gb_xiongmai_net_surveillance_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xiongmai/net_surveillance/http/detected",
                        "xiongmai/net_surveillance/auth_bypass_possible");

  script_xref(name:"URL", value:"https://sec-consult.com/blog/detail/millions-of-xiongmai-video-surveillance-devices-can-be-hacked-via-cloud-feature-xmeye-p2p-cloud/");
  script_xref(name:"URL", value:"https://securityledger.com/2016/10/shoddy-supply-chain-lurks-behind-mirai-botnet/");
  script_xref(name:"URL", value:"https://flashpoint.io/blog/mirai-botnet-when-vulnerabilities-travel-downstream/");
  script_xref(name:"URL", value:"https://krebsonsecurity.com/2016/10/europe-to-push-new-security-rules-amid-iot-mess/");
  script_xref(name:"URL", value:"https://krebsonsecurity.com/tag/xc3511/");
  script_xref(name:"URL", value:"https://github.com/daniel-beck/DWF-Database/blob/master/DWF-Database-2016.csv");

  script_tag(name:"summary", value:"The remote installation of HangZhou XiongMai Technologies Net
  Surveillance is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the '/DVR.html' page is accessible without
  authentication.");

  script_tag(name:"insight", value:"The installation of HangZhou XiongMai Technologies Net
  Surveillance allows any attacker to bypass the login screen to get full access to the camera feed
  and the version number.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information through the camera feed or to get access to a potentially vulnerable
  version.");

  script_tag(name:"affected", value:"Various HangZhou XiongMai Technologies DVRs, NVRs and IP
  cameras are known to be affected.

  Please note that this vulnerability affects a wide number of products and manufacturers that ship
  products based on the hardware and software shipped by HangZhou XiongMai Technologies.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!get_app_location(cpe: CPE, port: port, nofork: TRUE)) # nb: To have a reference to the Detection-VT
  exit(0);

if(get_kb_item("xiongmai/net_surveillance/" + port + "/auth_bypass_possible")) {
  vulnUrl = http_report_vuln_url(port: port, url: "/DVR.htm", url_only: TRUE);
  report = 'It was possible to bypass authentication and view the camera feed through the following URL:\n' + vulnUrl;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
