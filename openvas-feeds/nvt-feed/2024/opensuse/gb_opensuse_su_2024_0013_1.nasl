# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833781");
  script_cve_id("CVE-2022-47021");
  script_tag(name:"creation_date", value:"2024-03-04 12:50:37 +0000 (Mon, 04 Mar 2024)");
  script_version("2025-02-26T05:38:40+0000");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:40 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-27 14:45:49 +0000 (Fri, 27 Jan 2023)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0013-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0013-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OGZ3XSAOKYHWIRFP73YPJ33KTPBC6PEQ/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1207381");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opusfile' package(s) announced via the openSUSE-SU-2024:0013-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opusfile fixes the following issues:

- CVE-2022-47021: Fixed a NULL pointer dereference (boo#1207381)");

  script_tag(name:"affected", value:"'opusfile' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libopusfile0", rpm:"libopusfile0~0.12~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opusfile-devel", rpm:"opusfile-devel~0.12~bp155.3.3.1", rls:"openSUSELeap15.5"))) {
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
