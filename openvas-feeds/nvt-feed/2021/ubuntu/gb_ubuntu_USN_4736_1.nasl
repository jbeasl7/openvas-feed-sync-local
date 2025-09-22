# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844833");
  script_cve_id("CVE-2020-15685", "CVE-2020-26976", "CVE-2021-23953", "CVE-2021-23954", "CVE-2021-23960", "CVE-2021-23964");
  script_tag(name:"creation_date", value:"2021-02-17 04:00:24 +0000 (Wed, 17 Feb 2021)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-04 17:43:18 +0000 (Thu, 04 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-4736-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.10");

  script_xref(name:"Advisory-ID", value:"USN-4736-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4736-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-4736-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked into opening a specially crafted website in a browsing context,
an attacker could potentially exploit these to cause a denial of service,
obtain sensitive information, or execute arbitrary code. (CVE-2020-26976,
CVE-2021-23953, CVE-2021-23954, CVE-2021-23960, CVE-2021-23964)

It was discovered that responses received during the plaintext phase of
the STARTTLS connection setup were subsequently evaluated during the
encrypted session. A person in the middle could potentially exploit this
to perform a response injection attack. (CVE-2020-15685)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:78.7.1+build1-0ubuntu0.20.10.4", rls:"UBUNTU20.10"))) {
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
