# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886252");
  script_version("2024-04-18T05:05:33+0000");
  script_cve_id("CVE-2023-40546", "CVE-2023-40547", "CVE-2023-40548", "CVE-2023-40549", "CVE-2023-40550", "CVE-2023-40551");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-08 19:25:40 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:37:04 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for shim-unsigned-aarch64 (FEDORA-2024-2aa28a4cfc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2aa28a4cfc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BLTFSIWJDS3TAE7QCXWDDPMODDVUE7UR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shim-unsigned-aarch64'
  package(s) announced via the FEDORA-2024-2aa28a4cfc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Initial UEFI bootloader that handles chaining to a trusted full
bootloader under secure boot environments.");

  script_tag(name:"affected", value:"'shim-unsigned-aarch64' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"shim-unsigned-aarch64", rpm:"shim-unsigned-aarch64~15.8~2", rls:"FC38"))) {
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