# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886097");
  script_version("2025-01-13T08:32:03+0000");
  script_cve_id("CVE-2024-1938", "CVE-2024-1939");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-19 20:20:25 +0000 (Thu, 19 Dec 2024)");
  script_tag(name:"creation_date", value:"2024-03-08 02:18:39 +0000 (Fri, 08 Mar 2024)");
  script_name("Fedora: Security Advisory for cryptlib (FEDORA-2024-129d8ca6fc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-129d8ca6fc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EUV4ZCDAUFMCC4ZDXDBEZGSONAAUJ36S");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cryptlib'
  package(s) announced via the FEDORA-2024-129d8ca6fc advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cryptlib is a powerful security toolkit that allows even inexperienced crypto
programmers to easily add encryption and authentication services to their
software. The high-level interface provides anyone with the ability to add
strong security capabilities to an application in as little as half an hour,
without needing to know any of the low-level details that make the encryption
or authentication work.  Because of this, cryptlib dramatically reduces the
cost involved in adding security to new or existing applications.

At the highest level, cryptlib provides implementations of complete security
services such as S/MIME and PGP/OpenPGP secure enveloping, SSL/TLS and
SSH secure sessions, CA services such as CMP, SCEP, RTCS, and OCSP, and other
security operations such as secure time-stamping. Since cryptlib uses
industry-standard X.509, S/MIME, PGP/OpenPGP, and SSH/SSL/TLS data formats,
the resulting encrypted or signed data can be easily transported to other
systems and processed there, and cryptlib itself runs on virtually any
operating system - cryptlib doesn&#39, t tie you to a single system.
This allows email, files and EDI transactions to be authenticated with
digital signatures and encrypted in an industry-standard format.");

  script_tag(name:"affected", value:"'cryptlib' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
