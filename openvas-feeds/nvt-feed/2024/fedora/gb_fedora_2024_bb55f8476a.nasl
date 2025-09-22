# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887250");
  script_cve_id("CVE-2024-35241", "CVE-2024-35242");
  script_tag(name:"creation_date", value:"2024-06-21 04:07:36 +0000 (Fri, 21 Jun 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-bb55f8476a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-bb55f8476a");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-bb55f8476a");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2291429");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2291430");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2291431");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2291433");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'composer' package(s) announced via the FEDORA-2024-bb55f8476a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"**Version 2.7.7** 2024-06-10

 * Security: Fixed command injection via malicious git branch name (GHSA-47f6-5gq3-vx9c / **CVE-2024-35241**)
 * Security: Fixed multiple command injections via malicious git/hg branch names (GHSA-v9qv-c7wm-wgmf / **CVE-2024-35242**)
 * Fixed PSR violations for classes not matching the namespace of a rule being hidden, this may lead to new violations being shown (#11957)
 * Fixed UX when a plugin is still in vendor dir but is not required nor allowed anymore after changing branches (#12000)
 * Fixed new platform requirements from composer.json not being checked if the lock file is outdated (#12001)
 * Fixed secure-http checks that could be bypassed by using malformed URL formats (fa3b9582c)
 * Fixed Filesystem::isLocalPath including windows-specific checks on linux (3c37a67c)
 * Fixed perforce argument escaping (3773f775)
 * Fixed handling of zip bombs when extracting archives (de5f7e32)
 * Fixed Windows command parameter escaping to prevent abuse of unicode characters with best fit encoding conversion (3130a7455, 04a63b324)
 * Fixed ability for `config` command to remove autoload keys (#11967)
 * Fixed empty `type` support in `init` command (#11999)
 * Fixed git clone errors when `safe.bareRepository` is set to `strict` in the git config (#11969)
 * Fixed regression showing network errors on PHP <8.1 (#11974)
 * Fixed some color bleed from a few warnings (#11972)");

  script_tag(name:"affected", value:"'composer' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"composer", rpm:"composer~2.7.7~1.fc39", rls:"FC39"))) {
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
