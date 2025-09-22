# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105010");
  script_version("2025-01-17T05:37:18+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0160");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:29:00 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2014-04-09 09:54:09 +0200 (Wed, 09 Apr 2014)");
  script_name("OpenSSL TLS 'heartbeat' Extension Information Disclosure Vulnerability (STARTTLS Check)");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("Copyright (C) 2014 Greenbone AG");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66690");

  script_tag(name:"impact", value:"An attacker can exploit this issue to gain access to sensitive
  information that may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted TLS request and check the response.");

  script_tag(name:"insight", value:"The TLS and DTLS implementations do not properly handle
  Heartbeat Extension packets.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"OpenSSL is prone to an information disclosure vulnerability.

  This VT has been deprecated and merged into the VT 'OpenSSL TLS 'heartbeat' Extension Information Disclosure Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.103936).");

  script_tag(name:"affected", value:"OpenSSL 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, and
  1.0.1 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
