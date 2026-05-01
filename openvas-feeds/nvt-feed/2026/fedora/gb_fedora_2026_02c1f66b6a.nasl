# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.029911026698697");
  script_cve_id("CVE-2026-40176", "CVE-2026-40261");
  script_tag(name:"creation_date", value:"2026-04-16 05:05:42 +0000 (Thu, 16 Apr 2026)");
  script_version("2026-04-16T06:18:46+0000");
  script_tag(name:"last_modification", value:"2026-04-16 06:18:46 +0000 (Thu, 16 Apr 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-02c1f66b6a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-02c1f66b6a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-02c1f66b6a");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'composer' package(s) announced via the FEDORA-2026-02c1f66b6a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"### Version 2.9.7 - 2026-04-14

* Fixes regression calling custom script command aliases that are called a substring of a composer command (#12802)

----

### Version 2.9.6 - 2026-04-14

 * Security: Fixed command injection via malicious Perforce reference (GHSA-gqw4-4w2p-838q / **CVE-2026-40261**)
 * Security: Fixed command injection via malicious Perforce repository definition (GHSA-wg36-wvj6-r67p / **CVE-2026-40176**)
 * Security: Fixed git credentials remaining in git mirror .git/config after clone or update failed (2bcbfc3d)
 * Security: Fixed usage of insecure 3DES ciphers when ext-curl is missing (5e71d77e)
 * Security: Fixed Perforce unescaped user input in queryP4User shell command (ef3fc088)
 * Security: Hardened git/hg/perforce/fossil identifier validation to ensure branch names starting with `-` do not cause issues (6621d45, d836b90, 5e08c764)
 * Fixed inconsistent treatment of SingleCommandApplication script commands wrt autoloading (#12758)
 * Fixed GitHub API authentication errors not being visible to the user (#12737)
 * Fixed some platform package parsing failing when Composer runs in web SAPIs (#12735)
 * Fixed error reporting for clarity when a constraint cannot be parsed (#12743)");

  script_tag(name:"affected", value:"'composer' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"composer", rpm:"composer~2.9.7~1.fc43", rls:"FC43"))) {
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
