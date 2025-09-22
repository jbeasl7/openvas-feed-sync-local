# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.153814");
  script_version("2025-09-10T05:38:24+0000");
  script_tag(name:"last_modification", value:"2025-09-10 05:38:24 +0000 (Wed, 10 Sep 2025)");
  script_tag(name:"creation_date", value:"2025-01-20 04:22:56 +0000 (Mon, 20 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2024-54767");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("AVM FRITZ!Box Information Disclosure Vulnerability (Nov 2024) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_avm_fritz_box_consolidation.nasl");
  script_mandatory_keys("avm_fritz_box/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"AVM FRITZ!Box devices are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"An access control issue in the component /juis_boxinfo.xml
  allows attackers to obtain sensitive information without authentication.");

  script_tag(name:"affected", value:"AVM FRITZ!Box 7530 AX version 7.59. Other devices and versions
  might be affected as well.");

  script_tag(name:"solution", value:"No known solution is available as of 20th January, 2025.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/Shuanunio/CVE_Requests/blob/main/AVM/fritz/AVM_FRITZ%21Box_7530%20AX_unauthorized_access_vulnerability_first.md");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "//juis_boxinfo.xml";

if (http_vuln_check(port: port, url: url, pattern: "BoxInfo>", check_header: TRUE, icase: FALSE,
                    extra_check: "UpdateConfig>")) {
  report = http_report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
