# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.826998210100102");
  script_cve_id("CVE-2025-21607", "CVE-2025-26622", "CVE-2025-27104", "CVE-2025-27105");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-23 19:06:22 +0000 (Wed, 23 Apr 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-826c82e00f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-826c82e00f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-826c82e00f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318844");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2337821");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2347303");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2347304");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2347306");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2347307");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2347310");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2347311");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vyper' package(s) announced via the FEDORA-2025-826c82e00f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vyper ver. 0.4.1

----

Another one small fix

----

Fix for a few known issues");

  script_tag(name:"affected", value:"'vyper' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"vyper", rpm:"vyper~0.4.1~1.fc42", rls:"FC42"))) {
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
