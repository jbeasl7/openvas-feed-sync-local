# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845215");
  script_cve_id("CVE-2021-4126", "CVE-2021-4129", "CVE-2021-4140", "CVE-2021-43528", "CVE-2021-43536", "CVE-2021-43537", "CVE-2021-43538", "CVE-2021-43539", "CVE-2021-43541", "CVE-2021-43542", "CVE-2021-43543", "CVE-2021-43545", "CVE-2021-43546", "CVE-2021-44538", "CVE-2022-22737", "CVE-2022-22738", "CVE-2022-22739", "CVE-2022-22740", "CVE-2022-22741", "CVE-2022-22742", "CVE-2022-22743", "CVE-2022-22745", "CVE-2022-22747", "CVE-2022-22748", "CVE-2022-22751");
  script_tag(name:"creation_date", value:"2022-01-28 08:01:04 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-03 20:03:32 +0000 (Tue, 03 Jan 2023)");

  script_name("Ubuntu: Security Advisory (USN-5246-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU21\.10");

  script_xref(name:"Advisory-ID", value:"USN-5246-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5246-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-5246-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked into opening a specially crafted website in a browsing context, an
attacker could potentially exploit these to cause a denial of service,
obtain sensitive information, conduct spoofing attacks, bypass security
restrictions, or execute arbitrary code. (CVE-2021-4129, CVE-2021-4140,
CVE-2021-43536, CVE-2021-43537, CVE-2021-43538, CVE-2021-43539,
CVE-2021-43541, CVE-2021-43542, CVE-2021-43543, CVE-2021-43545,
CVE-2021-43656, CVE-2022-22737, CVE-2022-22738, CVE-2022-22739,
CVE-2022-22740, CVE-2022-22741, CVE-2022-22742, CVE-2022-22743,
CVE-2022-22745, CVE-2022-22747, CVE-2022-22748, CVE-2022-22751)

It was discovered that JavaScript was unexpectedly enabled in the
composition area. An attacker could potentially exploit this in
combination with another vulnerability, with unspecified impacts.
(CVE-2021-43528)

A buffer overflow was discovered in the Matrix chat library bundled with
Thunderbird. An attacker could potentially exploit this to cause a denial
of service, or execute arbitrary code. (CVE-2021-44538)

It was discovered that Thunderbird's OpenPGP integration only considered
the inner signed message when checking signature validity in a message
that contains an additional outer MIME layer. An attacker could
potentially exploit this to trick the user into thinking that a message
has a valid signature. (CVE-2021-4126)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 21.10.");

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

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:91.5.0+build1-0ubuntu0.21.10.1", rls:"UBUNTU21.10"))) {
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
