# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.979837098997999");
  script_cve_id("CVE-2025-23266", "CVE-2025-23267");
  script_tag(name:"creation_date", value:"2025-08-25 04:08:39 +0000 (Mon, 25 Aug 2025)");
  script_version("2025-08-25T05:40:31+0000");
  script_tag(name:"last_modification", value:"2025-08-25 05:40:31 +0000 (Mon, 25 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-ab370b9ac9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-ab370b9ac9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-ab370b9ac9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2375617");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2382219");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2387403");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'toolbox' package(s) announced via the FEDORA-2025-ab370b9ac9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"### Security fixes

* Bumped the minimum github.com/go-viper/mapstructure/v2 version to 2.3.0 for
 GHSA-fv92-fjc5-jj9h or GO-2025-3787
* Bumped the minimum github.com/NVIDIA/nvidia-container-toolkit version to
 1.17.8 for CVE-2025-23266 and CVE-2025-23267

### Bug fixes

* Improved error handling when creating symbolic links inside the container
 to initialize it
* Preserved environment variables set by a KDE session and Konsole
* Unbroke access to CA certificates in `sshd(8)` sessions (regression in 0.1.2)
* Unbroke overriding the `HOME` variable (regression in 0.0.90)

### Dependencies

* Bumped the minimum Go version to 1.22");

  script_tag(name:"affected", value:"'toolbox' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"toolbox", rpm:"toolbox~0.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"toolbox-debuginfo", rpm:"toolbox-debuginfo~0.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"toolbox-debugsource", rpm:"toolbox-debugsource~0.2~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"toolbox-tests", rpm:"toolbox-tests~0.2~1.fc41", rls:"FC41"))) {
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
