# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.1029101142974980");
  script_cve_id("CVE-2025-9566");
  script_tag(name:"creation_date", value:"2025-09-09 04:05:22 +0000 (Tue, 09 Sep 2025)");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-05 20:15:36 +0000 (Fri, 05 Sep 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-f9e142a4b0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-f9e142a4b0");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-f9e142a4b0");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2393153");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah, containers-common, podman' package(s) announced via the FEDORA-2025-f9e142a4b0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2025-9566

Automatic update for containers-common-0.64.2-1.fc41, buildah-1.41.4-1.fc41, podman-5.6.1-1.fc41.

##### **Changelog for containers-common**

```
* Wed Sep 03 2025 Packit <hello@packit.dev> - 5:0.64.2-1
- Update to 0.64.2 upstream release

```

##### **Changelog for buildah**

```
* Thu Sep 04 2025 Packit <hello@packit.dev> - 2:1.41.4-1
- Update to 1.41.4 upstream release

```

##### **Changelog for podman**

```
* Thu Sep 04 2025 Packit <hello@packit.dev> - 5:5.6.1-1
- Update to 5.6.1 upstream release

```");

  script_tag(name:"affected", value:"'buildah, containers-common, podman' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.41.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-debuginfo", rpm:"buildah-debuginfo~1.41.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-debugsource", rpm:"buildah-debugsource~1.41.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-tests", rpm:"buildah-tests~1.41.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"buildah-tests-debuginfo", rpm:"buildah-tests-debuginfo~1.41.4~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containers-common", rpm:"containers-common~0.64.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containers-common-extra", rpm:"containers-common-extra~0.64.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~5.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debuginfo", rpm:"podman-debuginfo~5.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debugsource", rpm:"podman-debugsource~5.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~5.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-machine", rpm:"podman-machine~5.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~5.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote-debuginfo", rpm:"podman-remote-debuginfo~5.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-tests", rpm:"podman-tests~5.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-tests-debuginfo", rpm:"podman-tests-debuginfo~5.6.1~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podmansh", rpm:"podmansh~5.6.1~1.fc41", rls:"FC41"))) {
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
