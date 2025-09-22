# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885127");
  script_version("2025-01-13T08:32:03+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-44487");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-14 01:15:00 +0000 (Sat, 14 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-11-05 02:18:43 +0000 (Sun, 05 Nov 2023)");
  script_name("Fedora: Security Advisory for proxygen (FEDORA-2023-7934802344)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-7934802344");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7W2TMDSEU343IYYSHVRRDSXFERPL2IDT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'proxygen'
  package(s) announced via the FEDORA-2023-7934802344 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Proxygen comprises the core C++ HTTP abstractions used at Facebook.
Internally, it is used as the basis for building many HTTP servers, proxies,
and clients. This release focuses on the common HTTP abstractions and our
simple HTTPServer framework. Future releases will provide simple client APIs
as well. The framework supports HTTP/1.1, SPDY/3, SPDY/3.1, HTTP/2, and
HTTP/3. The goal is to provide a simple, performant, and modern C++ HTTP
library.");

  script_tag(name:"affected", value:"'proxygen' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
