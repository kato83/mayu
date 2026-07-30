export interface CvssMetricValue {
  label: string;
  description: string;
}

export interface CvssMetricDefinition {
  name: string;
  values: Record<string, CvssMetricValue>;
}

export type CvssVersion = '2.0' | '3.0' | '3.1' | '4.0';

const CVSS_V2_DEFINITIONS: Record<string, CvssMetricDefinition> = {
  AV: {
    name: $localize`:@@cvssVector.v2.av.name:Access Vector`,
    values: {
      L: {
        label: $localize`:@@cvssVector.v2.av.l.label:Local`,
        description: $localize`:@@cvssVector.v2.av.l.desc:The vulnerability requires local access to the target system`,
      },
      A: {
        label: $localize`:@@cvssVector.v2.av.a.label:Adjacent Network`,
        description: $localize`:@@cvssVector.v2.av.a.desc:The vulnerability requires access to the local network`,
      },
      N: {
        label: $localize`:@@cvssVector.v2.av.n.label:Network`,
        description: $localize`:@@cvssVector.v2.av.n.desc:The vulnerability is exploitable remotely over the network`,
      },
    },
  },
  AC: {
    name: $localize`:@@cvssVector.v2.ac.name:Access Complexity`,
    values: {
      H: {
        label: $localize`:@@cvssVector.v2.ac.h.label:High`,
        description: $localize`:@@cvssVector.v2.ac.h.desc:Specialized conditions exist that make exploitation difficult`,
      },
      M: {
        label: $localize`:@@cvssVector.v2.ac.m.label:Medium`,
        description: $localize`:@@cvssVector.v2.ac.m.desc:Some conditions beyond the attacker's control must exist`,
      },
      L: {
        label: $localize`:@@cvssVector.v2.ac.l.label:Low`,
        description: $localize`:@@cvssVector.v2.ac.l.desc:No specialized conditions exist for exploitation`,
      },
    },
  },
  Au: {
    name: $localize`:@@cvssVector.v2.au.name:Authentication`,
    values: {
      M: {
        label: $localize`:@@cvssVector.v2.au.m.label:Multiple`,
        description: $localize`:@@cvssVector.v2.au.m.desc:Multiple instances of authentication are required`,
      },
      S: {
        label: $localize`:@@cvssVector.v2.au.s.label:Single`,
        description: $localize`:@@cvssVector.v2.au.s.desc:Single authentication is required`,
      },
      N: {
        label: $localize`:@@cvssVector.v2.au.n.label:None`,
        description: $localize`:@@cvssVector.v2.au.n.desc:No authentication is required`,
      },
    },
  },
  C: {
    name: $localize`:@@cvssVector.v2.c.name:Confidentiality Impact`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v2.c.n.label:None`,
        description: $localize`:@@cvssVector.v2.c.n.desc:No impact on confidentiality`,
      },
      P: {
        label: $localize`:@@cvssVector.v2.c.p.label:Partial`,
        description: $localize`:@@cvssVector.v2.c.p.desc:Partial disclosure of information`,
      },
      C: {
        label: $localize`:@@cvssVector.v2.c.c.label:Complete`,
        description: $localize`:@@cvssVector.v2.c.c.desc:Complete disclosure of all information`,
      },
    },
  },
  I: {
    name: $localize`:@@cvssVector.v2.i.name:Integrity Impact`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v2.i.n.label:None`,
        description: $localize`:@@cvssVector.v2.i.n.desc:No impact on integrity`,
      },
      P: {
        label: $localize`:@@cvssVector.v2.i.p.label:Partial`,
        description: $localize`:@@cvssVector.v2.i.p.desc:Partial modification of data is possible`,
      },
      C: {
        label: $localize`:@@cvssVector.v2.i.c.label:Complete`,
        description: $localize`:@@cvssVector.v2.i.c.desc:Complete modification of all data`,
      },
    },
  },
  A: {
    name: $localize`:@@cvssVector.v2.a.name:Availability Impact`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v2.a.n.label:None`,
        description: $localize`:@@cvssVector.v2.a.n.desc:No impact on availability`,
      },
      P: {
        label: $localize`:@@cvssVector.v2.a.p.label:Partial`,
        description: $localize`:@@cvssVector.v2.a.p.desc:Partial disruption of availability`,
      },
      C: {
        label: $localize`:@@cvssVector.v2.a.c.label:Complete`,
        description: $localize`:@@cvssVector.v2.a.c.desc:Complete shutdown of the affected resource`,
      },
    },
  },
};

const CVSS_V3_DEFINITIONS: Record<string, CvssMetricDefinition> = {
  AV: {
    name: $localize`:@@cvssVector.v3.av.name:Attack Vector`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v3.av.n.label:Network`,
        description: $localize`:@@cvssVector.v3.av.n.desc:The vulnerability is exploitable remotely over the network`,
      },
      A: {
        label: $localize`:@@cvssVector.v3.av.a.label:Adjacent`,
        description: $localize`:@@cvssVector.v3.av.a.desc:The attack is limited to the same shared physical or logical network`,
      },
      L: {
        label: $localize`:@@cvssVector.v3.av.l.label:Local`,
        description: $localize`:@@cvssVector.v3.av.l.desc:The vulnerability requires local access`,
      },
      P: {
        label: $localize`:@@cvssVector.v3.av.p.label:Physical`,
        description: $localize`:@@cvssVector.v3.av.p.desc:The attack requires physical access to the target`,
      },
    },
  },
  AC: {
    name: $localize`:@@cvssVector.v3.ac.name:Attack Complexity`,
    values: {
      L: {
        label: $localize`:@@cvssVector.v3.ac.l.label:Low`,
        description: $localize`:@@cvssVector.v3.ac.l.desc:No specialized conditions exist for exploitation`,
      },
      H: {
        label: $localize`:@@cvssVector.v3.ac.h.label:High`,
        description: $localize`:@@cvssVector.v3.ac.h.desc:Conditions beyond the attacker's control must exist`,
      },
    },
  },
  PR: {
    name: $localize`:@@cvssVector.v3.pr.name:Privileges Required`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v3.pr.n.label:None`,
        description: $localize`:@@cvssVector.v3.pr.n.desc:No privileges are required`,
      },
      L: {
        label: $localize`:@@cvssVector.v3.pr.l.label:Low`,
        description: $localize`:@@cvssVector.v3.pr.l.desc:Basic user privileges are required`,
      },
      H: {
        label: $localize`:@@cvssVector.v3.pr.h.label:High`,
        description: $localize`:@@cvssVector.v3.pr.h.desc:Administrative privileges are required`,
      },
    },
  },
  UI: {
    name: $localize`:@@cvssVector.v3.ui.name:User Interaction`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v3.ui.n.label:None`,
        description: $localize`:@@cvssVector.v3.ui.n.desc:No user interaction is required`,
      },
      R: {
        label: $localize`:@@cvssVector.v3.ui.r.label:Required`,
        description: $localize`:@@cvssVector.v3.ui.r.desc:User interaction is required for exploitation`,
      },
    },
  },
  S: {
    name: $localize`:@@cvssVector.v3.s.name:Scope`,
    values: {
      U: {
        label: $localize`:@@cvssVector.v3.s.u.label:Unchanged`,
        description: $localize`:@@cvssVector.v3.s.u.desc:The exploited vulnerability cannot affect other components`,
      },
      C: {
        label: $localize`:@@cvssVector.v3.s.c.label:Changed`,
        description: $localize`:@@cvssVector.v3.s.c.desc:The exploited vulnerability can affect other components`,
      },
    },
  },
  C: {
    name: $localize`:@@cvssVector.v3.c.name:Confidentiality`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v3.c.n.label:None`,
        description: $localize`:@@cvssVector.v3.c.n.desc:No impact on confidentiality`,
      },
      L: {
        label: $localize`:@@cvssVector.v3.c.l.label:Low`,
        description: $localize`:@@cvssVector.v3.c.l.desc:Limited information disclosure`,
      },
      H: {
        label: $localize`:@@cvssVector.v3.c.h.label:High`,
        description: $localize`:@@cvssVector.v3.c.h.desc:Total information disclosure`,
      },
    },
  },
  I: {
    name: $localize`:@@cvssVector.v3.i.name:Integrity`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v3.i.n.label:None`,
        description: $localize`:@@cvssVector.v3.i.n.desc:No impact on integrity`,
      },
      L: {
        label: $localize`:@@cvssVector.v3.i.l.label:Low`,
        description: $localize`:@@cvssVector.v3.i.l.desc:Limited data modification`,
      },
      H: {
        label: $localize`:@@cvssVector.v3.i.h.label:High`,
        description: $localize`:@@cvssVector.v3.i.h.desc:Total data modification`,
      },
    },
  },
  A: {
    name: $localize`:@@cvssVector.v3.a.name:Availability`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v3.a.n.label:None`,
        description: $localize`:@@cvssVector.v3.a.n.desc:No impact on availability`,
      },
      L: {
        label: $localize`:@@cvssVector.v3.a.l.label:Low`,
        description: $localize`:@@cvssVector.v3.a.l.desc:Reduced performance or partial disruption`,
      },
      H: {
        label: $localize`:@@cvssVector.v3.a.h.label:High`,
        description: $localize`:@@cvssVector.v3.a.h.desc:Total loss of availability`,
      },
    },
  },
};

const CVSS_V4_DEFINITIONS: Record<string, CvssMetricDefinition> = {
  AV: {
    name: $localize`:@@cvssVector.v4.av.name:Attack Vector`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v4.av.n.label:Network`,
        description: $localize`:@@cvssVector.v4.av.n.desc:The vulnerability is exploitable remotely over the network`,
      },
      A: {
        label: $localize`:@@cvssVector.v4.av.a.label:Adjacent`,
        description: $localize`:@@cvssVector.v4.av.a.desc:The attack is limited to the same shared network`,
      },
      L: {
        label: $localize`:@@cvssVector.v4.av.l.label:Local`,
        description: $localize`:@@cvssVector.v4.av.l.desc:The vulnerability requires local access`,
      },
      P: {
        label: $localize`:@@cvssVector.v4.av.p.label:Physical`,
        description: $localize`:@@cvssVector.v4.av.p.desc:The attack requires physical access to the target`,
      },
    },
  },
  AC: {
    name: $localize`:@@cvssVector.v4.ac.name:Attack Complexity`,
    values: {
      L: {
        label: $localize`:@@cvssVector.v4.ac.l.label:Low`,
        description: $localize`:@@cvssVector.v4.ac.l.desc:No specialized conditions exist for exploitation`,
      },
      H: {
        label: $localize`:@@cvssVector.v4.ac.h.label:High`,
        description: $localize`:@@cvssVector.v4.ac.h.desc:Conditions beyond the attacker's control must exist`,
      },
    },
  },
  AT: {
    name: $localize`:@@cvssVector.v4.at.name:Attack Requirements`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v4.at.n.label:None`,
        description: $localize`:@@cvssVector.v4.at.n.desc:No additional conditions are required`,
      },
      P: {
        label: $localize`:@@cvssVector.v4.at.p.label:Present`,
        description: $localize`:@@cvssVector.v4.at.p.desc:Additional conditions must be present for exploitation`,
      },
    },
  },
  PR: {
    name: $localize`:@@cvssVector.v4.pr.name:Privileges Required`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v4.pr.n.label:None`,
        description: $localize`:@@cvssVector.v4.pr.n.desc:No privileges are required`,
      },
      L: {
        label: $localize`:@@cvssVector.v4.pr.l.label:Low`,
        description: $localize`:@@cvssVector.v4.pr.l.desc:Basic user privileges are required`,
      },
      H: {
        label: $localize`:@@cvssVector.v4.pr.h.label:High`,
        description: $localize`:@@cvssVector.v4.pr.h.desc:Administrative privileges are required`,
      },
    },
  },
  UI: {
    name: $localize`:@@cvssVector.v4.ui.name:User Interaction`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v4.ui.n.label:None`,
        description: $localize`:@@cvssVector.v4.ui.n.desc:No user interaction is required`,
      },
      P: {
        label: $localize`:@@cvssVector.v4.ui.p.label:Passive`,
        description: $localize`:@@cvssVector.v4.ui.p.desc:Limited user interaction is required`,
      },
      A: {
        label: $localize`:@@cvssVector.v4.ui.a.label:Active`,
        description: $localize`:@@cvssVector.v4.ui.a.desc:Active user interaction is required`,
      },
    },
  },
  VC: {
    name: $localize`:@@cvssVector.v4.vc.name:Vulnerable System Confidentiality`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v4.vc.n.label:None`,
        description: $localize`:@@cvssVector.v4.vc.n.desc:No impact on vulnerable system confidentiality`,
      },
      L: {
        label: $localize`:@@cvssVector.v4.vc.l.label:Low`,
        description: $localize`:@@cvssVector.v4.vc.l.desc:Limited confidentiality impact on the vulnerable system`,
      },
      H: {
        label: $localize`:@@cvssVector.v4.vc.h.label:High`,
        description: $localize`:@@cvssVector.v4.vc.h.desc:Total confidentiality loss on the vulnerable system`,
      },
    },
  },
  VI: {
    name: $localize`:@@cvssVector.v4.vi.name:Vulnerable System Integrity`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v4.vi.n.label:None`,
        description: $localize`:@@cvssVector.v4.vi.n.desc:No impact on vulnerable system integrity`,
      },
      L: {
        label: $localize`:@@cvssVector.v4.vi.l.label:Low`,
        description: $localize`:@@cvssVector.v4.vi.l.desc:Limited integrity impact on the vulnerable system`,
      },
      H: {
        label: $localize`:@@cvssVector.v4.vi.h.label:High`,
        description: $localize`:@@cvssVector.v4.vi.h.desc:Total integrity loss on the vulnerable system`,
      },
    },
  },
  VA: {
    name: $localize`:@@cvssVector.v4.va.name:Vulnerable System Availability`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v4.va.n.label:None`,
        description: $localize`:@@cvssVector.v4.va.n.desc:No impact on vulnerable system availability`,
      },
      L: {
        label: $localize`:@@cvssVector.v4.va.l.label:Low`,
        description: $localize`:@@cvssVector.v4.va.l.desc:Limited availability impact on the vulnerable system`,
      },
      H: {
        label: $localize`:@@cvssVector.v4.va.h.label:High`,
        description: $localize`:@@cvssVector.v4.va.h.desc:Total availability loss on the vulnerable system`,
      },
    },
  },
  SC: {
    name: $localize`:@@cvssVector.v4.sc.name:Subsequent System Confidentiality`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v4.sc.n.label:None`,
        description: $localize`:@@cvssVector.v4.sc.n.desc:No impact on subsequent system confidentiality`,
      },
      L: {
        label: $localize`:@@cvssVector.v4.sc.l.label:Low`,
        description: $localize`:@@cvssVector.v4.sc.l.desc:Limited confidentiality impact on subsequent systems`,
      },
      H: {
        label: $localize`:@@cvssVector.v4.sc.h.label:High`,
        description: $localize`:@@cvssVector.v4.sc.h.desc:Total confidentiality loss on subsequent systems`,
      },
    },
  },
  SI: {
    name: $localize`:@@cvssVector.v4.si.name:Subsequent System Integrity`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v4.si.n.label:None`,
        description: $localize`:@@cvssVector.v4.si.n.desc:No impact on subsequent system integrity`,
      },
      L: {
        label: $localize`:@@cvssVector.v4.si.l.label:Low`,
        description: $localize`:@@cvssVector.v4.si.l.desc:Limited integrity impact on subsequent systems`,
      },
      H: {
        label: $localize`:@@cvssVector.v4.si.h.label:High`,
        description: $localize`:@@cvssVector.v4.si.h.desc:Total integrity loss on subsequent systems`,
      },
    },
  },
  SA: {
    name: $localize`:@@cvssVector.v4.sa.name:Subsequent System Availability`,
    values: {
      N: {
        label: $localize`:@@cvssVector.v4.sa.n.label:None`,
        description: $localize`:@@cvssVector.v4.sa.n.desc:No impact on subsequent system availability`,
      },
      L: {
        label: $localize`:@@cvssVector.v4.sa.l.label:Low`,
        description: $localize`:@@cvssVector.v4.sa.l.desc:Limited availability impact on subsequent systems`,
      },
      H: {
        label: $localize`:@@cvssVector.v4.sa.h.label:High`,
        description: $localize`:@@cvssVector.v4.sa.h.desc:Total availability loss on subsequent systems`,
      },
    },
  },
};

export const CVSS_DEFINITIONS: Record<CvssVersion, Record<string, CvssMetricDefinition>> = {
  '2.0': CVSS_V2_DEFINITIONS,
  '3.0': CVSS_V3_DEFINITIONS,
  '3.1': CVSS_V3_DEFINITIONS,
  '4.0': CVSS_V4_DEFINITIONS,
};
