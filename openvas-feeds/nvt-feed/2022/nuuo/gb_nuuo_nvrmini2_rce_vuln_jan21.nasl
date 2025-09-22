# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nuuo:nuuo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147455");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2022-01-18 05:19:54 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-21 18:51:00 +0000 (Fri, 21 Jan 2022)");

  script_cve_id("CVE-2011-5325", "CVE-2022-23227");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("NUUO NVRmini 2 <= 03.11.0000.0016 RCE Vulnerability - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_nuuo_devices_http_detect.nasl");
  script_mandatory_keys("nuuo/device/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"NUUO NVRmini 2 devices are prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"NUUO NVRmini 2 allows an unauthenticated attacker to upload an
  encrypted TAR archive, which can be abused to add arbitrary users because of the lack of
  handle_import_user.php authentication. When combined with another flaw (CVE-2011-5325), it is
  possible to overwrite arbitrary files under the web root and achieve code execution as root.");

  script_tag(name:"affected", value:"NUUO NVRmini 2 devices in version 03.11.0000.0016 and prior
  are known to be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"https://github.com/pedrib/PoC/blob/master/advisories/NUUO/nuuo_nvrmini_round2.mkd");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

url = "/handle_import_user.php";

if (http_vuln_check(port: port, url: url, pattern: "There was an error uploading the file",
                    check_header: TRUE)) {
  report = "It was possible to access " + http_report_vuln_url(port: port, url: url, url_only: TRUE) +
           " without authentication.";
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
