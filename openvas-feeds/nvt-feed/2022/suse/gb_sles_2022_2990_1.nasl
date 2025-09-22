# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2990.1");
  script_cve_id("CVE-2021-21261", "CVE-2021-21381");
  script_tag(name:"creation_date", value:"2022-09-02 04:52:13 +0000 (Fri, 02 Sep 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-22 01:49:11 +0000 (Fri, 22 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2990-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2990-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222990-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1155688");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180996");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1183459");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-September/012061.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flatpak' package(s) announced via the SUSE-SU-2022:2990-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for flatpak fixes the following issues:

- CVE-2021-21381: Fixed an issue where a sandboxed application could
 read and write arbitrary host files via special tokens in the
 .desktop file (bsc#1183459).
- CVE-2021-21261: Fixed a sandbox escape issue via the flatpak-portal
 service (bsc#1180996).

Non-security fixes:

- openh264 extension needs to use 'extra_data'. (bsc#1155688)
 The update will provide the support for extra_data' in extensions
 and will provide a list of versions that are supported. This will
 be useful for the extra_data for extensions because that will require
 it to say that it is supported for version > 1.2.5 in the 1.2 series
 and > 1.4.2 otherwise.
 The update will includes fixes for a segfault in the function that
 lists the installed references (flatpak_installation_list_installed_refs).
 When an appstream update is cancelled while downloading icons, the update
 will show a proper fail. Before this fix the next update attempt will see
 an up-to-date timestamp, think everything is ok and not download the missing icons.
 The update will introduce checks in the OCI (Open Container Initiative format)
 updates for validating if it is gpg verified.
 The update will install the required runtime for the installed extension.
 The update will prevent a crash if the 'FlatpakDir' can't ensure it has a repo configured.
 The update will prevent the removal of local extensions considered remote and not locally related.");

  script_tag(name:"affected", value:"'flatpak' package(s) on SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.2.3~150100.4.5.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-devel", rpm:"flatpak-devel~1.2.3~150100.4.5.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-zsh-completion", rpm:"flatpak-zsh-completion~1.2.3~150100.4.5.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0", rpm:"libflatpak0~1.2.3~150100.4.5.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Flatpak-1_0", rpm:"typelib-1_0-Flatpak-1_0~1.2.3~150100.4.5.2", rls:"SLES15.0SP1"))) {
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
