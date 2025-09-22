# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02817.1");
  script_cve_id("CVE-2025-48174", "CVE-2025-48175");
  script_tag(name:"creation_date", value:"2025-08-18 04:22:46 +0000 (Mon, 18 Aug 2025)");
  script_version("2025-08-18T05:42:33+0000");
  script_tag(name:"last_modification", value:"2025-08-18 05:42:33 +0000 (Mon, 18 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-04 20:02:37 +0000 (Wed, 04 Jun 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02817-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02817-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502817-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243269");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243270");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041222.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libavif' package(s) announced via the SUSE-SU-2025:02817-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libavif fixes the following issues:

- update to 1.3.0:
- CVE-2025-48175: Fixed an integer overflows in multiplications involving rgbRowBytes, yRowBytes, uRowBytes, and vRowBytes. (bsc#1243270)
- CVE-2025-48174: Fixed an integer overflow and resultant buffer overflow in stream->offset+size. (bsc#1243269)");

  script_tag(name:"affected", value:"'libavif' package(s) on SUSE Linux Enterprise Server 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libavif16", rpm:"libavif16~1.3.0~150600.3.5.1", rls:"SLES15.0SP6"))) {
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
