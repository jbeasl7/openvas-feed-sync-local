# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856841");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-9341", "CVE-2024-9407", "CVE-2024-9675", "CVE-2024-9676");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-22 19:34:40 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-12-13 05:00:29 +0000 (Fri, 13 Dec 2024)");
  script_name("openSUSE: Security Advisory for buildah (SUSE-SU-2024:4303-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4303-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BVDZUEHEJC6XMYQYX6D4ORCVEDNXJR7U");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'buildah'
  package(s) announced via the SUSE-SU-2024:4303-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for buildah fixes the following issues:

  Security issues fixed:

  * CVE-2024-9675: cache arbitrary directory mount (bsc#1231499)

  * CVE-2024-9407: Improper Input Validation in bind-propagation Option of
      Dockerfile RUN --mount Instruction (bsc#1231208)

  * CVE-2024-9676: symlink traversal vulnerability in the containers/storage
      library can cause denial of service (bsc#1231698)

  * CVE-2024-9341: FIPS Crypto-Policy Directory Mounting Issue in
      containers/common Go Library (bsc#1231230)

  Non-security issue fixed:

  * default to slirp4netns on SLE instead of pasta (bsc#1232522)");

  script_tag(name:"affected", value:"'buildah' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"buildah", rpm:"buildah~1.35.4~150300.8.28.3", rls:"openSUSELeap15.3"))) {
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
