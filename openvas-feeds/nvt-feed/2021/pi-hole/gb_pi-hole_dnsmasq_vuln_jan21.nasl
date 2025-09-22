# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pi-hole:ftldns";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117175");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-01-22 10:39:33 +0000 (Fri, 22 Jan 2021)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-26 18:22:00 +0000 (Fri, 26 Mar 2021)");

  script_cve_id("CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685",
                "CVE-2020-25686", "CVE-2020-25687");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pi-hole FTL DNS < 5.5 Multiple Vulnerabilities in Dnsmasq (DNSpooq)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("General");
  script_dependencies("gb_pi-hole_http_detect.nasl");
  script_mandatory_keys("pi-hole/detected");

  script_tag(name:"summary", value:"Dnsmasq as used in the 'FTL DNS' component of Pi-hole is prone
  to multiple vulnerabilities dubbed 'DNSpooq'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist in Dnsmasq versions prior to 2.83 as
  used in the 'FTL' component:

  - CVE-2020-25681: A heap-based buffer overflow in sort_rrset() when DNSSEC is used

  - CVE-2020-25682: A buffer overflow in extract_name() function due to missing length check, when
  DNSSEC is enabled

  - CVE-2020-25683: A heap-based buffer overflow when DNSSEC is enabled. This flaw is caused by the
  lack of length checks in rfc1035.c:extract_name(), which could be abused to make the code execute
  memcpy() with a negative size in get_rdata()

  - CVE-2020-25684: A lack of proper address/port check implemented in the reply_query function

  - CVE-2020-25685: A lack of query resource name (RRNAME) checks implemented in the reply_query
  function

  - CVE-2020-25686: Multiple DNS query requests for the same resource name (RRNAME) allows for
  remote attackers to spoof DNS traffic, using a birthday attack (RFC 5452)

  - CVE-2020-25687: A heap-based buffer overflow with large memcpy in sort_rrset() when DNSSEC is
  enabled. This flaw is caused by the lack of length checks in rfc1035.c:extract_name(), which could
  be abused to make the code execute memcpy() with a negative size in sort_rrset()");

  script_tag(name:"impact", value:"- CVE-2020-25681: This can allow a remote attacker to write
  arbitrary data into target device's memory that can lead to memory corruption and other unexpected
  behaviors on the target device

  - CVE-2020-25682: This can allow a remote attacker to cause memory corruption on the target device

  - CVE-2020-25683: A remote attacker, who can create valid DNS replies, could use this flaw to cause
  an overflow in a heap-allocated memory. This flaw could be abused to make the code execute memcpy()
  with a negative size in get_rdata() and cause a crash in dnsmasq, resulting in a Denial of Service

  - CVE-2020-25684: This flaw makes it easier to forge replies to an off-path attacker

  - CVE-2020-25685: This flaw allows remote attackers to spoof DNS traffic that can lead to DNS cache
  poisoning

  - CVE-2020-25686: This flaw can lead to DNS cache poisoning

  - CVE-2020-25687: A remote attacker, who can create valid DNS replies, could use this flaw to cause
  an overflow in a heap-allocated memory. This flaw could be abused be abused to make the code execute
  memcpy() with a negative size in sort_rrset() and cause a crash in dnsmasq, resulting in a Denial of
  Service");

  script_tag(name:"affected", value:"Pi-hole FTL DNS versions prior to 5.5.");

  script_tag(name:"solution", value:"Update to version 5.5 or later.");

  script_xref(name:"URL", value:"https://pi-hole.net/2021/01/19/pi-hole-ftl-v5-5-released-update-today/");
  script_xref(name:"URL", value:"https://www.jsof-tech.com/disclosures/dnspooq/");
  script_xref(name:"URL", value:"https://www.thekelleys.org.uk/dnsmasq/CHANGELOG");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
