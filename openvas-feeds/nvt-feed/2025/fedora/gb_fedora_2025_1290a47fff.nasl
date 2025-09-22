# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.12909747102102102");
  script_cve_id("CVE-2023-40022", "CVE-2024-31668", "CVE-2024-31669", "CVE-2024-31670", "CVE-2024-53256");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-30 19:50:45 +0000 (Wed, 30 Aug 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2025-1290a47fff)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-1290a47fff");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-1290a47fff");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333933");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2333934");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2340020");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2346253");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cutter-re, rizin' package(s) announced via the FEDORA-2025-1290a47fff advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-40022 rizin: Integer Overflow in C++ demangler logic
CVE-2024-31669 rizin: Uncontrolled Resource Consumption via bin_pe_parse_imports
CVE-2024-31670 rizin: buffer overflow via create_cache_bins
CVE-2024-31668 rizin: improper neutralization of special elements via meta_set function
CVE-2024-53256 rizin: Rizin has a command injection via RzBinInfo bclass due legacy code");

  script_tag(name:"affected", value:"'cutter-re, rizin' package(s) on Fedora 41.");

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

  if(!isnull(res = isrpmvuln(pkg:"cutter-re", rpm:"cutter-re~2.3.4~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cutter-re-debuginfo", rpm:"cutter-re-debuginfo~2.3.4~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cutter-re-debugsource", rpm:"cutter-re-debugsource~2.3.4~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cutter-re-devel", rpm:"cutter-re-devel~2.3.4~6.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin", rpm:"rizin~0.7.4~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin-common", rpm:"rizin-common~0.7.4~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin-debuginfo", rpm:"rizin-debuginfo~0.7.4~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin-debugsource", rpm:"rizin-debugsource~0.7.4~5.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rizin-devel", rpm:"rizin-devel~0.7.4~5.fc41", rls:"FC41"))) {
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
