# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openprinting:cups";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114789");
  script_version("2024-10-08T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-10-08 05:05:46 +0000 (Tue, 08 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-09-27 11:38:09 +0000 (Fri, 27 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2024-47076", "CVE-2024-47175", "CVE-2024-47176", "CVE-2024-47177",
                "CVE-2024-47850");

  # For now we only know remotely that a system *might* use the affected components so a quite low
  # QoD was used here.
  script_tag(name:"qod_type", value:"general_note");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("CUPS Multiple Vulnerabilities (Sep/Oct 2024)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_cups_http_detect.nasl");
  script_mandatory_keys("cups/detected");

  script_tag(name:"summary", value:"Various components of CUPS are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2024-47076: cfGetPrinterAttributes5 does not validate IPP attributes returned from an IPP
  server (libcupsfilters)

  - CVE-2024-47175: ppdCreatePPDFromIPP2 does not sanitize IPP attributes when creating the PPD
  buffer (libppd)

  - CVE-2024-47176: Multiple bugs leading to info leak and remote code execution (cups-browsed)

  - CVE-2024-47177: Command injection via FoomaticRIPCommandLine (cups-filters)

  - CVE-2024-47850: Distributed denial-of-service (DDoS) attacks (cups-browsed)");

  script_tag(name:"impact", value:"Various flaws chained together could allow a remote code
  execution (RCE) on the affected host.");

  script_tag(name:"affected", value:"All CUPS systems which have the affected component(s)
  installed.");

  script_tag(name:"solution", value:"No known solution is available as of 07th October, 2024.
  Information regarding this issue will be updated once solution details are available.

  Applying one of the following mitigations seems to close the initial attack vector:

  - disable / remove the 'cups-browsed' package / service

  - edit the /etc/cups/cups-browsed.conf configuration based on the vendor guidance in the
  referenced advisories");

  script_xref(name:"URL", value:"https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/");
  script_xref(name:"URL", value:"https://openprinting.github.io/OpenPrinting-News-Flash-cups-browsed-Remote-Code-Execution-vulnerability/");
  script_xref(name:"URL", value:"https://isc.sans.edu/diary/Patch+for+Critical+CUPS+vulnerability+Dont+Panic/31302");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/09/26/5");
  script_xref(name:"URL", value:"https://gist.github.com/stong/c8847ef27910ae344a7b5408d9840ee1");
  script_xref(name:"URL", value:"https://access.redhat.com/security/vulnerabilities/RHSB-2024-002");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/libcupsfilters/security/advisories/GHSA-w63j-6g73-wmg5");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/libppd/security/advisories/GHSA-7xfx-47qg-grp6");
  script_xref(name:"URL", value:"https://github.com/OpenPrinting/cups-filters/security/advisories/GHSA-p9rh-jxmq-gq47");
  script_xref(name:"URL", value:"https://github.com/RickdeJager/cupshax");
  script_xref(name:"URL", value:"https://www.akamai.com/blog/security-research/october-cups-ddos-threat");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

report = report_fixed_ver(installed_version: version, fixed_version: "None");
security_message(port: port, data: report);
exit(0);
