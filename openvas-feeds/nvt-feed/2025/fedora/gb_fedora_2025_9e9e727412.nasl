# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.91019101727412");
  script_cve_id("CVE-2025-9019", "CVE-2025-9157", "CVE-2025-9384", "CVE-2025-9385", "CVE-2025-9386");
  script_tag(name:"creation_date", value:"2025-09-08 04:05:06 +0000 (Mon, 08 Sep 2025)");
  script_version("2025-09-12T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-12 05:38:45 +0000 (Fri, 12 Sep 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-11 17:53:34 +0000 (Thu, 11 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-9e9e727412)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-9e9e727412");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-9e9e727412");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388758");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388759");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388760");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388763");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2388764");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389866");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389867");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2389868");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2392223");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2392224");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2392225");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2392226");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2392227");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2392228");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2392231");
  script_xref(name:"URL", value:"https://github.com/appneta/tcpreplay/releases/tag/v4.5.2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpreplay' package(s) announced via the FEDORA-2025-9e9e727412 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mostly bugfix release. More info here:

[link moved to references]");

  script_tag(name:"affected", value:"'tcpreplay' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"tcpreplay", rpm:"tcpreplay~4.5.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpreplay-debuginfo", rpm:"tcpreplay-debuginfo~4.5.2~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcpreplay-debugsource", rpm:"tcpreplay-debugsource~4.5.2~1.fc42", rls:"FC42"))) {
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
