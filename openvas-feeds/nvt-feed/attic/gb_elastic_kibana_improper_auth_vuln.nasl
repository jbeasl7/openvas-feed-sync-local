# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811410");
  script_version("2025-09-03T14:11:39+0000");
  script_cve_id("CVE-2016-10364");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 17:30:00 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-07-03 20:27:52 +0530 (Mon, 03 Jul 2017)");
  script_name("Elasticsearch Kibana Improper Authentication Vulnerability");

  script_tag(name:"summary", value:"Elasticsearch Kibana is prone to an improper authentication vulnerability.

  This VT has been split into two VTs with the OIDs 1.3.6.1.4.1.25623.1.0.108259 and 1.3.6.1.4.1.25623.1.0.108260");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper authentication to
  requests to advanced settings and the short URL service.");

  script_tag(name:"impact", value:"Successful exploitation will lead an
  authenticated user to make requests to advanced settings and the short URL
  services regardless of their own permissions.");

  script_tag(name:"affected", value:"Elasticsearch Kibana version 5.0.0 and 5.0.1.");

  script_tag(name:"solution", value:"Update to Elasticsearch Kibana version
  5.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);