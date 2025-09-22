# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.10210010097979710291020");
  script_cve_id("CVE-2025-40918");
  script_tag(name:"creation_date", value:"2025-08-14 04:10:50 +0000 (Thu, 14 Aug 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-fddaaaf9f0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-fddaaaf9f0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-fddaaaf9f0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2381432");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Authen-SASL' package(s) announced via the FEDORA-2025-fddaaaf9f0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"2.1900
[Fixed] - CVE-2025-40918 (Insecure source of randomness), required addition of dependency on Crypt::URandom
[Changed] - Modules Authen::SASL::Perl::CRAM_MD5, Authen::SASL::Perl::DIGEST_MD5 and Authen::SASL::CRAM_MD5 marked as deprecated based on the respective RFC documents,
- Update module metadata to point to the new 'perl-authen-sasl' org on GitHub to which the modules moved
- Use VERSION declarations in 'package' statements, since our minimum Perl version is 5.14 anyway");

  script_tag(name:"affected", value:"'perl-Authen-SASL' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Authen-SASL", rpm:"perl-Authen-SASL~2.1900~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Authen-SASL-tests", rpm:"perl-Authen-SASL-tests~2.1900~1.fc42", rls:"FC42"))) {
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
