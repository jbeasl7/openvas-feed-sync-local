# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2018.1611");
  script_cve_id("CVE-2014-9317", "CVE-2015-6761", "CVE-2015-6818", "CVE-2015-6820", "CVE-2015-6821", "CVE-2015-6822", "CVE-2015-6823", "CVE-2015-6824", "CVE-2015-6825", "CVE-2015-6826", "CVE-2015-8216", "CVE-2015-8217", "CVE-2015-8363", "CVE-2015-8364", "CVE-2015-8661", "CVE-2015-8662", "CVE-2015-8663", "CVE-2016-10190", "CVE-2016-10191");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-21 11:29:00 +0000 (Fri, 21 Dec 2018)");

  script_name("Debian: Security Advisory (DLA-1611)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1611");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1611-2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libav' package(s) announced via the DLA-1611 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two more security issues have been corrected in the libav multimedia library. This is a follow-up announcement for DLA-1611-1.

CVE-2015-6823

The allocate_buffers function in libavcodec/alac.c did not initialize certain context data, which allowed remote attackers to cause a denial of service (segmentation violation) or possibly have unspecified other impact via crafted Apple Lossless Audio Codec (ALAC) data. This issues has now been addressed by clearing pointers in avcodec/alac.c's allocate_buffers().

Other than stated in debian/changelog of upload 6:11.12-1~deb8u2, this issue only now got fixed with upload of 6:11.12-1~deb8u3.

CVE-2015-6824

The sws_init_context function in libswscale/utils.c did not initialize certain pixbuf data structures, which allowed remote attackers to cause a denial of service (segmentation violation) or possibly have unspecified other impact via crafted video data. In swscale/utils.c now these pix buffers get cleared which fixes use of uninitialized memory.

Other than stated in debian/changelog of upload 6:11.12-1~deb8u2, this issue only now got fixed with upload of 6:11.12-1~deb8u3.

For Debian 8 Jessie, these problems have been fixed in version 6:11.12-1~deb8u3.

We recommend that you upgrade your libav packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]

This VT has been deprecated as a duplicate of the VT 'Debian: Security Advisory (DLA-1611)' (OID: 1.3.6.1.4.1.25623.1.0.891611)");

  script_tag(name:"affected", value:"'libav' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
