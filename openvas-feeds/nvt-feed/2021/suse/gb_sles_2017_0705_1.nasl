# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0705.1");
  script_cve_id("CVE-2015-5191");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"3.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-08 14:19:25 +0000 (Tue, 08 Aug 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0705-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0705-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170705-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1006796");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1007600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1013496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913727");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/938593");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/941384");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944615");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/952645");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/985110");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/994598");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-March/002699.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'open-vm-tools' package(s) announced via the SUSE-SU-2017:0705-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for open-vm-tools to 10.1.0 stable brings features, fixes bugs and security issues:

- New vmware-namespace-cmd command line utility
- GTK3 support
- Common Agent Framework (CAF)
- Guest authentication with xmlsec1
- Sub-command to push updated network information to the host on demand
- Fix for quiesced snapshot failure leaving guest file system quiesced (bsc#1006796)
- Fix for CVE-2015-5191 (bsc#1007600)
- Report SLES for SAP 12 guest OS as SLES 12 (bsc#1013496)
- Add udev rule to increase VMware virtual disk timeout values (bsc#994598)
- Fix vmtoolsd init script to run vmtoolsd in background (bsc#971031)
- Fix copy-n-paste and drag-n-drop regressions (bsc#978424)
- Add new vmblock-fuse.service
- Fix a suspend with systemd issue (bsc#913727)
- ESXi Serviceability
- GuestInfo Enhancements
- Compatibility with all supported versions of VMware vSphere, VMware Workstation 12.0
 and VMware Fusion 8.0.");

  script_tag(name:"affected", value:"'open-vm-tools' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libvmtools0", rpm:"libvmtools0~10.1.0~7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools", rpm:"open-vm-tools~10.1.0~7.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"open-vm-tools-desktop", rpm:"open-vm-tools-desktop~10.1.0~7.1", rls:"SLES11.0SP4"))) {
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
