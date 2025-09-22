# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0798.1");
  script_cve_id("CVE-2016-10163", "CVE-2016-10214", "CVE-2017-5580", "CVE-2017-5937", "CVE-2017-5956", "CVE-2017-5957", "CVE-2017-5993", "CVE-2017-5994", "CVE-2017-6209", "CVE-2017-6210", "CVE-2017-6317", "CVE-2017-6355", "CVE-2017-6386");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-16 17:55:03 +0000 (Thu, 16 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0798-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0798-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170798-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021616");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1021627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024232");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024992");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024993");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025505");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1025507");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1026922");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027108");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1027376");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-March/002738.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virglrenderer' package(s) announced via the SUSE-SU-2017:0798-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virglrenderer fixes the following issues:

Security issues fixed:
- CVE-2017-6386: memory leakage while in vrend_create_vertex_elements_state (bsc#1027376)
- CVE-2017-6355: integer overflow while creating shader object (bsc#1027108)
- CVE-2017-6317: fix memory leak in add shader program (bsc#1026922)
- CVE-2017-6210: null pointer dereference in vrend_decode_reset (bsc#1026725)
- CVE-2017-6209: stack buffer oveflow in parse_identifier (bsc#1026723)
- CVE-2017-5994: out-of-bounds access in vrend_create_vertex_elements_state (bsc#1025507)
- CVE-2017-5993: host memory leakage when initialising blitter context (bsc#1025505)
- CVE-2017-5957: stack overflow in vrend_decode_set_framebuffer_state (bsc#1024993)
- CVE-2017-5956: OOB access while in vrend_draw_vbo (bsc#1024992)
- CVE-2017-5937: null pointer dereference in vrend_clear (bsc#1024232)
- CVE-2017-5580: OOB access while parsing texture instruction (bsc#1021627)
- CVE-2016-10214: host memory leak issue in virgl_resource_attach_backing (bsc#1024244)
- CVE-2016-10163: host memory leakage when creating decode context (bsc#1021616)");

  script_tag(name:"affected", value:"'virglrenderer' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libvirglrenderer0", rpm:"libvirglrenderer0~0.5.0~11.1", rls:"SLES12.0SP2"))) {
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
