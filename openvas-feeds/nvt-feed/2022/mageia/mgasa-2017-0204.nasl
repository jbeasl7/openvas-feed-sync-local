# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0204");
  script_cve_id("CVE-2016-5325", "CVE-2016-7099");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-10-12 15:10:44 +0000 (Wed, 12 Oct 2016)");

  script_name("Mageia: Security Advisory (MGASA-2017-0204)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0204");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0204.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19550");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2016-10/msg00013.html");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v0.10.47/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v0.10.48/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/september-2016-security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the MGASA-2017-0204 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Node.js has a defect that may make HTTP response splitting possible
under certain circumstances. If user-input is passed to the reason
argument to writeHead() on an HTTP response, a new-line character may be
used to inject additional responses (CVE-2016-5325).

The tls.checkServerIdentity function in Node.js 0.10.x before 0.10.47 does
not properly handle wildcards in name fields of X.509 certificates, which
allows man-in-the-middle attackers to spoof servers via a crafted
certificate (CVE-2016-7099).");

  script_tag(name:"affected", value:"'nodejs' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~0.10.48~1.mga5", rls:"MAGEIA5"))) {
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
