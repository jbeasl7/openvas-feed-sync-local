# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.981001004994639");
  script_cve_id("CVE-2025-3066", "CVE-2025-3067", "CVE-2025-3068", "CVE-2025-3069", "CVE-2025-3070", "CVE-2025-3071", "CVE-2025-3072", "CVE-2025-3073", "CVE-2025-3074");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-98dd4c4639)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-98dd4c4639");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-98dd4c4639");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356787");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356788");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356789");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356790");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356792");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356793");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356794");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356795");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356796");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356797");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356798");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356799");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356800");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2025-98dd4c4639 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 135.0.7049.52

* High CVE-2025-3066: Use after free in Navigations
* Medium CVE-2025-3067: Inappropriate implementation in Custom Tabs
* Medium CVE-2025-3068: Inappropriate implementation in Intents
* Medium CVE-2025-3069: Inappropriate implementation in Extensions
* Medium CVE-2025-3070: Insufficient validation of untrusted input in Extensions
* Low CVE-2025-3071: Inappropriate implementation in Navigations
* Low CVE-2025-3072: Inappropriate implementation in Custom Tabs
* Low CVE-2025-3073: Inappropriate implementation in Autofill
* Low CVE-2025-3074: Inappropriate implementation in Downloads");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~135.0.7049.52~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~135.0.7049.52~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~135.0.7049.52~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~135.0.7049.52~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~135.0.7049.52~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~135.0.7049.52~1.fc41", rls:"FC41"))) {
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
