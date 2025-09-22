# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0151");
  script_cve_id("CVE-2015-2928", "CVE-2015-2929");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-01 17:28:13 +0000 (Sat, 01 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0151)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0151");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0151.html");
  script_xref(name:"URL", value:"https://blog.torproject.org/blog/tor-02512-and-0267-are-released");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15639");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3216");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tor' package(s) announced via the MGASA-2015-0151 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"'disgleirio' discovered that a malicious client could trigger an assertion
failure in a Tor instance providing a hidden service, thus rendering the
service inaccessible (CVE-2015-2928).

'DonnchaC' discovered that Tor clients would crash with an assertion failure
upon parsing specially crafted hidden service descriptors (CVE-2015-2929).

Introduction points would accept multiple INTRODUCE1 cells on one circuit,
making it inexpensive for an attacker to overload a hidden service with
introductions. Introduction points now no longer allow multiple cells of
that type on the same circuit.

The tor package has been updated to version 0.2.4.27, fixing these issues.");

  script_tag(name:"affected", value:"'tor' package(s) on Mageia 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"tor", rpm:"tor~0.2.4.27~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
