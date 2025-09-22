# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.698599549810005");
  script_cve_id("CVE-2025-2588");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-21 12:15:26 +0000 (Fri, 21 Mar 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-6b5c54bd05)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-6b5c54bd05");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-6b5c54bd05");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2354446");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'augeas' package(s) announced via the FEDORA-2025-6b5c54bd05 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2025-2588");

  script_tag(name:"affected", value:"'augeas' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"augeas", rpm:"augeas~1.14.2~0.4.20250324git4dffa3d.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"augeas-bash-completion", rpm:"augeas-bash-completion~1.14.2~0.4.20250324git4dffa3d.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"augeas-debuginfo", rpm:"augeas-debuginfo~1.14.2~0.4.20250324git4dffa3d.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"augeas-debugsource", rpm:"augeas-debugsource~1.14.2~0.4.20250324git4dffa3d.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"augeas-devel", rpm:"augeas-devel~1.14.2~0.4.20250324git4dffa3d.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"augeas-libs", rpm:"augeas-libs~1.14.2~0.4.20250324git4dffa3d.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"augeas-libs-debuginfo", rpm:"augeas-libs-debuginfo~1.14.2~0.4.20250324git4dffa3d.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"augeas-static", rpm:"augeas-static~1.14.2~0.4.20250324git4dffa3d.fc42", rls:"FC42"))) {
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
